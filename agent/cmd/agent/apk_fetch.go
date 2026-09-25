package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// An orchestrator that sees apk_fetch_v1 sends update_ref instead of the
// APK inside the pull answer. The worker then fetches the APK in chunks into
// distributor/tw/.tmp, in the background so config apply, ack and heartbeat
// never wait for it, checks it against the signed manifest and only then
// publishes it and the manifest.
const (
	apkChunkSize     = 4 << 20
	apkMaxSize       = 512 << 20
	apkChunkPause    = time.Second
	apkChunkAttempts = 5
	apkTmpDir        = ".tmp"
)

var apkSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type orchUpdateRef struct {
	APKSeq          int64  `json:"apk_seq"`
	APKName         string `json:"apk_name"`
	APKSHA256       string `json:"apk_sha256"`
	APKSize         int64  `json:"apk_size"`
	ManifestJSON    string `json:"manifest_json"`
	ManifestMinisig string `json:"manifest_minisig"`
}

type orchAPKChunkRequest struct {
	WorkerID  string `json:"worker_id"`
	APKSeq    int64  `json:"apk_seq"`
	APKSHA256 string `json:"apk_sha256"`
	Offset    int64  `json:"offset"`
	Length    int64  `json:"length"`
}

type orchAPKChunkResponse struct {
	OK         bool   `json:"ok"`
	Code       string `json:"code,omitempty"`
	Error      string `json:"error,omitempty"`
	TotalSize  int64  `json:"total_size"`
	DataBase64 string `json:"data_base64"`
}

type apkChunkFetcher interface {
	apkChunk(ctx context.Context, req orchAPKChunkRequest) (orchAPKChunkResponse, error)
}

func (c *orchClient) apkChunk(ctx context.Context, req orchAPKChunkRequest) (orchAPKChunkResponse, error) {
	var resp orchAPKChunkResponse
	err := c.noiseCall(ctx, "/w/v1/apk/chunk", req, &resp)
	return resp, err
}

// apkDownloader runs at most one download at a time.
type apkDownloader struct {
	mu      sync.Mutex
	running string // sha256 being downloaded
	done    chan struct{}
}

// handle publishes the release named by ref: the manifest alone when the
// APK is already here, otherwise after a background download.
func (d *apkDownloader) handle(ctx context.Context, cfg envConfig, client apkChunkFetcher, workerID string, ref orchUpdateRef) {
	if err := validateUpdateRef(ref); err != nil {
		slog.Warn("apk update_ref ignored", "err", err)
		return
	}
	if err := checkUpdateManifestSignature(cfg.StateDir, ref.ManifestJSON, ref.ManifestMinisig); err != nil {
		slog.Warn("apk update_ref ignored", "err", err)
		return
	}
	if apkAlreadyPublished(cfg.StateDir, ref) {
		if err := publishUpdateManifest(cfg.StateDir, ref.ManifestJSON, ref.ManifestMinisig); err != nil {
			slog.Warn("apk manifest publish failed", "err", err)
		}
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running != "" {
		return
	}
	d.running = ref.APKSHA256
	d.done = make(chan struct{})
	go func() {
		defer func() {
			d.mu.Lock()
			d.running = ""
			close(d.done)
			d.mu.Unlock()
		}()
		if err := downloadAPK(ctx, cfg, client, workerID, ref); err != nil {
			slog.Warn("apk download failed; will retry on a later pull", "apk", ref.APKName, "err", err)
			return
		}
		slog.Info("apk published", "apk", ref.APKName, "seq", ref.APKSeq)
	}()
}

// wait blocks until a running download ends (tests).
func (d *apkDownloader) wait() {
	d.mu.Lock()
	done := d.done
	d.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (d *apkDownloader) inProgress() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

func validateUpdateRef(ref orchUpdateRef) error {
	if !apkSHA256Pattern.MatchString(ref.APKSHA256) {
		return errors.New("apk_sha256 must be 64 lowercase hex characters")
	}
	if name := ref.APKName; name == "" || filepath.Base(name) != name || !strings.HasSuffix(name, ".apk") || strings.HasPrefix(name, ".") {
		return fmt.Errorf("apk_name %q is not a plain .apk file name", sanitizeLogValue(ref.APKName))
	}
	if ref.APKSize <= 0 || ref.APKSize > apkMaxSize {
		return fmt.Errorf("apk_size %d out of range", ref.APKSize)
	}
	if strings.TrimSpace(ref.ManifestJSON) == "" || strings.TrimSpace(ref.ManifestMinisig) == "" {
		return errors.New("manifest or signature missing")
	}
	manifestSHA, err := updateManifestAPKSHA256(ref.ManifestJSON)
	if err != nil {
		return err
	}
	if manifestSHA != ref.APKSHA256 {
		return errors.New("apk_sha256 does not match the signed manifest")
	}
	return nil
}

func apkAlreadyPublished(stateDir string, ref orchUpdateRef) bool {
	path := filepath.Join(stateDir, "distributor", "tw", ref.APKName)
	info, err := os.Stat(path)
	if err != nil || info.Size() != ref.APKSize {
		return false
	}
	sum, err := fileSHA256(path)
	return err == nil && sum == ref.APKSHA256
}

func downloadAPK(ctx context.Context, cfg envConfig, client apkChunkFetcher, workerID string, ref orchUpdateRef) error {
	twDir := filepath.Join(cfg.StateDir, "distributor", "tw")
	partPath := filepath.Join(twDir, apkTmpDir, ref.APKSHA256+".part")
	if err := os.MkdirAll(filepath.Dir(partPath), 0o755); err != nil {
		return err
	}
	part, err := os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer part.Close()
	info, err := part.Stat()
	if err != nil {
		return err
	}
	// Resume where an earlier attempt stopped.
	offset := info.Size()
	if offset > ref.APKSize {
		offset = 0
	}
	if err := part.Truncate(offset); err != nil {
		return err
	}
	failures := 0
	for offset < ref.APKSize {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		length := min(int64(apkChunkSize), ref.APKSize-offset)
		resp, err := client.apkChunk(ctx, orchAPKChunkRequest{
			WorkerID: workerID, APKSeq: ref.APKSeq, APKSHA256: ref.APKSHA256, Offset: offset, Length: length,
		})
		if err == nil && !resp.OK {
			switch resp.Code {
			case "release_superseded", "worker_revoked":
				_ = os.Remove(partPath)
				return fmt.Errorf("orchestrator stopped the download: %s", resp.Code)
			case "bad_range":
				offset = 0
				if err := part.Truncate(0); err != nil {
					return err
				}
			}
			err = fmt.Errorf("chunk rejected: %s %s", resp.Code, resp.Error)
		}
		var data []byte
		if err == nil {
			if resp.TotalSize != 0 && resp.TotalSize != ref.APKSize {
				_ = os.Remove(partPath)
				return fmt.Errorf("orchestrator reports size %d, update_ref %d", resp.TotalSize, ref.APKSize)
			}
			data, err = base64.StdEncoding.DecodeString(resp.DataBase64)
			if err == nil && (len(data) == 0 || int64(len(data)) > length) {
				err = fmt.Errorf("chunk at %d has %d bytes, asked for %d", offset, len(data), length)
			}
		}
		if err != nil {
			failures++
			if failures >= apkChunkAttempts {
				return err
			}
			sleepCtx(ctx, time.Duration(failures)*apkChunkPause*5)
			continue
		}
		failures = 0
		if _, err := part.WriteAt(data, offset); err != nil {
			return err
		}
		offset += int64(len(data))
		// Each chunk is a separate handshake from the worker's budget.
		sleepCtx(ctx, apkChunkPause)
	}
	if err := part.Sync(); err != nil {
		return err
	}
	if err := part.Close(); err != nil {
		return err
	}
	sum, err := fileSHA256(partPath)
	if err != nil {
		return err
	}
	if sum != ref.APKSHA256 {
		_ = os.Remove(partPath)
		return errors.New("downloaded apk does not match the manifest sha256")
	}
	if err := os.Chmod(partPath, 0o644); err != nil {
		return err
	}
	if err := os.Rename(partPath, filepath.Join(twDir, ref.APKName)); err != nil {
		return err
	}
	if err := syncDir(twDir); err != nil {
		return err
	}
	if err := publishUpdateManifest(cfg.StateDir, ref.ManifestJSON, ref.ManifestMinisig); err != nil {
		return err
	}
	return cleanupDistributedAPKs(cfg.StateDir, "")
}

// publishUpdateManifest writes the manifest and its signature once the APK
// they describe is in place. An expired manifest is not published.
func publishUpdateManifest(stateDir, manifestJSON, minisig string) error {
	if manifestExpired(manifestJSON, platformNow()) {
		return errors.New("update manifest has expired")
	}
	if err := checkUpdateManifestSignature(stateDir, manifestJSON, minisig); err != nil {
		return err
	}
	twDir := filepath.Join(stateDir, "distributor", "tw")
	if err := writeFile(filepath.Join(twDir, "update-manifest.json"), []byte(strings.TrimSpace(manifestJSON)), 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(twDir, "update-manifest.json.minisig"), []byte(strings.TrimSpace(minisig)), 0o644); err != nil {
		return err
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// manifestExpired reports whether the manifest's expires_at (or expiresAt)
// is in the past. A manifest without it is left to the client to judge.
func manifestExpired(manifestJSON string, now time.Time) bool {
	var root map[string]any
	if err := json.Unmarshal([]byte(manifestJSON), &root); err != nil {
		return false
	}
	for _, key := range []string{"expires_at", "expiresAt"} {
		if value := stringFromAny(root[key]); value != "" {
			expires, err := time.Parse(time.RFC3339, value)
			return err == nil && !now.Before(expires)
		}
	}
	return false
}

// cleanupDistributedAPKs removes APKs and partial downloads the current
// manifest does not reference (WRK-L6), and withdraws an expired manifest.
// Everything else in distributor/tw is left alone.
func cleanupDistributedAPKs(stateDir, downloading string) error {
	twDir := filepath.Join(stateDir, "distributor", "tw")
	manifestPath := filepath.Join(twDir, "update-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		// Without a manifest nothing says which APK is current.
		return nil
	}
	if manifestExpired(string(raw), platformNow()) {
		slog.Warn("update manifest expired; withdrawing it")
		var errs []error
		for _, name := range []string{"update-manifest.json", "update-manifest.json.minisig"} {
			if err := os.Remove(filepath.Join(twDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	keepAPK := currentManifestAPKName(raw)
	if keepAPK == "" {
		return nil
	}
	var errs []error
	entries, err := os.ReadDir(twDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type().IsRegular() && strings.HasSuffix(name, ".apk") && name != keepAPK {
			if err := os.Remove(filepath.Join(twDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	tmpEntries, _ := os.ReadDir(filepath.Join(twDir, apkTmpDir))
	for _, entry := range tmpEntries {
		if downloading != "" && entry.Name() == downloading+".part" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(twDir, apkTmpDir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func currentManifestAPKName(raw []byte) string {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return ""
	}
	if nested, ok := root["distributed_apk"].(map[string]any); ok {
		root = nested
	}
	name := filepath.Base(stringFromAny(root["apk_name"]))
	if name == "." || name == "/" || !strings.HasSuffix(name, ".apk") {
		return ""
	}
	return name
}
