package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeChunkServer struct {
	mu       sync.Mutex
	apk      []byte
	requests []orchAPKChunkRequest
	code     string
	corrupt  bool
}

func (f *fakeChunkServer) apkChunk(_ context.Context, req orchAPKChunkRequest) (orchAPKChunkResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	if f.code != "" {
		return orchAPKChunkResponse{Code: f.code, Error: f.code}, nil
	}
	end := min(req.Offset+req.Length, int64(len(f.apk)))
	data := append([]byte(nil), f.apk[req.Offset:end]...)
	if f.corrupt {
		data[0] ^= 0xff
	}
	return orchAPKChunkResponse{OK: true, TotalSize: int64(len(f.apk)), DataBase64: base64.StdEncoding.EncodeToString(data)}, nil
}

func testAPKRef(t *testing.T, apk []byte, name string, expires time.Time) orchUpdateRef {
	t.Helper()
	sum := sha256.Sum256(apk)
	sha := hex.EncodeToString(sum[:])
	manifest := fmt.Sprintf(`{"schema":1,"ns":"apk-update-v1","seq":7,"version_code":131,"apk_sha256":"%s","apk_name":"%s","expires_at":"%s"}`, sha, name, expires.UTC().Format(time.RFC3339))
	return orchUpdateRef{APKSeq: 7, APKName: name, APKSHA256: sha, APKSize: int64(len(apk)), ManifestJSON: manifest, ManifestMinisig: "untrusted comment: sig\nRWQ"}
}

func testAPKBytes(n int) []byte {
	apk := make([]byte, n)
	for i := range apk {
		apk[i] = byte(i * 7)
	}
	return apk
}

func TestValidateUpdateRef(t *testing.T) {
	good := testAPKRef(t, []byte("apk"), "app.apk", time.Now().Add(time.Hour))
	if err := validateUpdateRef(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*orchUpdateRef){
		"upper sha":      func(r *orchUpdateRef) { r.APKSHA256 = strings.ToUpper(r.APKSHA256) },
		"path name":      func(r *orchUpdateRef) { r.APKName = "../app.apk" },
		"not apk":        func(r *orchUpdateRef) { r.APKName = "config.json" },
		"hidden":         func(r *orchUpdateRef) { r.APKName = ".x.apk" },
		"zero size":      func(r *orchUpdateRef) { r.APKSize = 0 },
		"huge":           func(r *orchUpdateRef) { r.APKSize = apkMaxSize + 1 },
		"no signature":   func(r *orchUpdateRef) { r.ManifestMinisig = "" },
		"sha ≠ manifest": func(r *orchUpdateRef) { r.APKSHA256 = strings.Repeat("0", 64) },
	} {
		ref := good
		mutate(&ref)
		if err := validateUpdateRef(ref); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestDownloadAPKResumesVerifiesAndPublishes(t *testing.T) {
	stateDir := t.TempDir()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	apk := testAPKBytes(apkChunkSize + 1234)
	ref := testAPKRef(t, apk, "app-v2.apk", time.Now().Add(time.Hour))
	// An earlier attempt left part of the file, an old release and a stale
	// partial download; config.json must be left alone.
	for name, data := range map[string][]byte{
		filepath.Join(apkTmpDir, ref.APKSHA256+".part"): apk[:1000],
		filepath.Join(apkTmpDir, "old.part"):            []byte("x"),
		"app-v1.apk":                                    []byte("old"),
		"config.json":                                   []byte("{}"),
	} {
		if err := writeFile(filepath.Join(twDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	server := &fakeChunkServer{apk: apk}
	if err := downloadAPK(t.Context(), envConfig{StateDir: stateDir}, server, "w1", ref); err != nil {
		t.Fatal(err)
	}
	if server.requests[0].Offset != 1000 {
		t.Fatalf("download did not resume: first offset %d", server.requests[0].Offset)
	}
	for _, req := range server.requests {
		if req.Length > apkChunkSize || req.WorkerID != "w1" || req.APKSHA256 != ref.APKSHA256 || req.APKSeq != 7 {
			t.Fatalf("bad chunk request %+v", req)
		}
	}
	got, err := os.ReadFile(filepath.Join(twDir, "app-v2.apk"))
	if err != nil || string(got) != string(apk) {
		t.Fatalf("published apk differs: %v", err)
	}
	manifest, _ := os.ReadFile(filepath.Join(twDir, "update-manifest.json"))
	if !strings.Contains(string(manifest), ref.APKSHA256) || !fileExists(filepath.Join(twDir, "update-manifest.json.minisig")) {
		t.Fatalf("manifest not published: %s", manifest)
	}
	for _, gone := range []string{"app-v1.apk", filepath.Join(apkTmpDir, "old.part"), filepath.Join(apkTmpDir, ref.APKSHA256+".part")} {
		if fileExists(filepath.Join(twDir, gone)) {
			t.Fatalf("%s not cleaned up", gone)
		}
	}
	if !fileExists(filepath.Join(twDir, "config.json")) {
		t.Fatal("cleanup removed config.json")
	}
}

func TestDownloadAPKRejectsCorruptData(t *testing.T) {
	stateDir := t.TempDir()
	apk := testAPKBytes(3000)
	ref := testAPKRef(t, apk, "app.apk", time.Now().Add(time.Hour))
	err := downloadAPK(t.Context(), envConfig{StateDir: stateDir}, &fakeChunkServer{apk: apk, corrupt: true}, "w1", ref)
	if err == nil {
		t.Fatal("corrupt apk accepted")
	}
	twDir := filepath.Join(stateDir, "distributor", "tw")
	if fileExists(filepath.Join(twDir, "app.apk")) || fileExists(filepath.Join(twDir, "update-manifest.json")) {
		t.Fatal("corrupt apk or its manifest published")
	}
}

func TestDownloadAPKStopsWhenSuperseded(t *testing.T) {
	stateDir := t.TempDir()
	apk := testAPKBytes(3000)
	ref := testAPKRef(t, apk, "app.apk", time.Now().Add(time.Hour))
	server := &fakeChunkServer{apk: apk, code: "release_superseded"}
	if err := downloadAPK(t.Context(), envConfig{StateDir: stateDir}, server, "w1", ref); err == nil {
		t.Fatal("superseded download reported success")
	}
	if len(server.requests) != 1 {
		t.Fatalf("download kept asking after release_superseded: %d requests", len(server.requests))
	}
}

func TestPublishedAPKOnlyRewritesManifest(t *testing.T) {
	stateDir := t.TempDir()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	apk := testAPKBytes(3000)
	ref := testAPKRef(t, apk, "app.apk", time.Now().Add(time.Hour))
	if err := writeFile(filepath.Join(twDir, "app.apk"), apk, 0o644); err != nil {
		t.Fatal(err)
	}
	server := &fakeChunkServer{apk: apk}
	d := &apkDownloader{}
	d.handle(t.Context(), envConfig{StateDir: stateDir}, server, "w1", ref)
	d.wait()
	if len(server.requests) != 0 {
		t.Fatalf("already published apk downloaded again: %d requests", len(server.requests))
	}
	if manifest, _ := os.ReadFile(filepath.Join(twDir, "update-manifest.json")); !strings.Contains(string(manifest), `"seq":7`) {
		t.Fatalf("reissued manifest not written: %s", manifest)
	}
}

func TestExpiredManifestIsNotServed(t *testing.T) {
	stateDir := t.TempDir()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	apk := testAPKBytes(100)
	expired := testAPKRef(t, apk, "app.apk", time.Now().Add(-time.Hour))
	if err := publishUpdateManifest(stateDir, expired.ManifestJSON, expired.ManifestMinisig); err == nil {
		t.Fatal("expired manifest published")
	}
	// A manifest that expires while published is withdrawn by the cleanup.
	for name, data := range map[string]string{"update-manifest.json": expired.ManifestJSON, "update-manifest.json.minisig": "sig", "app.apk": "apk"} {
		if err := writeFile(filepath.Join(twDir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := cleanupDistributedAPKs(stateDir, nil); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(twDir, "update-manifest.json")) || fileExists(filepath.Join(twDir, "update-manifest.json.minisig")) {
		t.Fatal("expired manifest still served")
	}
}

func TestInlineAPKFailureDoesNotBlockConfig(t *testing.T) {
	priv, pubText := testSigner(t)
	cfg := envConfig{StateDir: t.TempDir(), DisableSmokePeers: true}
	state := orchState{WorkerID: "w", SignerPublicKey: pubText, AppliedSeq: 1}
	worker := signedBundleForTest(t, priv, pubText, "worker-config-v1", 2, `,"desired_state":{"approved_devices":[]}`)
	client := signedBundleForTest(t, priv, pubText, "client-config-v1", 2, "")
	broken := &orchUpdateArtifact{ManifestJSON: `{"apk_sha256":"` + strings.Repeat("a", 64) + `"}`, ManifestMinisig: "sig", APKName: "app.apk", APKBase64: base64.StdEncoding.EncodeToString([]byte("not it"))}
	seq, _, err := applyOrchBundles(cfg, hardeningTestState(), state, worker, client, broken)
	if err != nil || seq != 2 {
		t.Fatalf("config not applied because of the apk: seq=%d err=%v", seq, err)
	}
	if !fileExists(filepath.Join(cfg.StateDir, "distributor", "tw", "config.json")) {
		t.Fatal("client config not published")
	}
}

func TestPullWithUpdateRefFetchesAPKInBackground(t *testing.T) {
	apk := testAPKBytes(5000)
	ref := testAPKRef(t, apk, "app.apk", time.Now().Add(time.Hour))
	server := &fakeChunkServer{apk: apk}
	f := newFakeOrchestrator(t, func(path string, raw json.RawMessage) any {
		switch {
		case strings.HasSuffix(path, "/config/pull"):
			return map[string]any{"ok": true, "status": "active", "not_modified": true, "update_ref": ref}
		case strings.HasSuffix(path, "/apk/chunk"):
			var req orchAPKChunkRequest
			_ = json.Unmarshal(raw, &req)
			resp, _ := server.apkChunk(context.Background(), req)
			return resp
		default:
			return map[string]any{"ok": true, "heartbeat": true}
		}
	})
	cfg := envConfig{StateDir: t.TempDir()}
	if err := saveOrchState(cfg.StateDir, orchState{WorkerID: "w1", AppliedSeq: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runOrchestratorLoop(ctx, cfg, hardeningTestState(), f.client(cfg))
	}()
	apkPath := filepath.Join(cfg.StateDir, "distributor", "tw", "app.apk")
	deadline := time.Now().Add(10 * time.Second)
	for !fileExists(apkPath) {
		if time.Now().After(deadline) {
			t.Fatal("apk not fetched")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if len(f.requestsTo("/w/v1/nudge/wait")) == 0 {
		t.Fatal("heartbeat waited for the apk download")
	}
	var pull orchPullRequest
	_ = json.Unmarshal(f.requestsTo("/w/v1/config/pull")[0], &pull)
	if !strings.Contains(strings.Join(pull.WorkerCapabilities, ","), "apk_fetch_v1") {
		t.Fatalf("pull does not declare apk_fetch_v1: %v", pull.WorkerCapabilities)
	}
}

func TestSplitUsageReports(t *testing.T) {
	if got := splitUsageReports(nil, 3); len(got) != 1 || len(got[0]) != 0 {
		t.Fatalf("empty usage: %v", got)
	}
	usage := make([]orchUsageReport, 7)
	got := splitUsageReports(usage, 3)
	if len(got) != 3 || len(got[0]) != 3 || len(got[2]) != 1 {
		t.Fatalf("split: %v", got)
	}
}

// publishTestManifest publishes a release as if an earlier download had
// finished, so the cleanup has a current manifest to go by.
func publishTestManifest(t *testing.T, stateDir string, ref orchUpdateRef, apk []byte) {
	t.Helper()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	if err := writeFile(filepath.Join(twDir, ref.APKName), apk, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publishUpdateManifest(stateDir, ref.ManifestJSON, ref.ManifestMinisig); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupKeepsAPKWhoseManifestIsBeingPublished(t *testing.T) {
	// The periodic cleanup runs on the loop while the download goroutine
	// moves the new APK in place and then publishes its manifest.
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stateDir := t.TempDir()
			twDir := filepath.Join(stateDir, "distributor", "tw")
			oldAPK := testAPKBytes(100 + i)
			if err := writeFile(filepath.Join(twDir, "app-v1.apk"), oldAPK, 0o644); err != nil {
				t.Error(err)
				return
			}
			old := testAPKRef(t, oldAPK, "app-v1.apk", time.Now().Add(time.Hour))
			if err := publishUpdateManifest(stateDir, old.ManifestJSON, old.ManifestMinisig); err != nil {
				t.Error(err)
				return
			}
			apk := testAPKBytes(3000 + i)
			ref := testAPKRef(t, apk, "app-v2.apk", time.Now().Add(time.Hour))
			d := &apkDownloader{}
			d.handle(t.Context(), envConfig{StateDir: stateDir}, &fakeChunkServer{apk: apk}, "w1", ref)
			finished := make(chan struct{})
			go func() {
				d.wait()
				close(finished)
			}()
			for running := true; running; {
				select {
				case <-finished:
					running = false
				default:
				}
				if err := cleanupDistributedAPKs(stateDir, d.pendingRef()); err != nil {
					t.Error(err)
					return
				}
			}
			manifest, _ := os.ReadFile(filepath.Join(twDir, "update-manifest.json"))
			if !strings.Contains(string(manifest), ref.APKSHA256) {
				t.Errorf("new manifest not published: %s", manifest)
				return
			}
			if !fileExists(filepath.Join(twDir, "app-v2.apk")) {
				t.Error("manifest published for an APK the cleanup removed")
			}
		}()
	}
	wg.Wait()
}

// cancellingChunkServer serves one chunk and then ends the attempt, like a
// download cut short by a network error.
type cancellingChunkServer struct {
	fakeChunkServer
	cancel context.CancelFunc
}

func (c *cancellingChunkServer) apkChunk(ctx context.Context, req orchAPKChunkRequest) (orchAPKChunkResponse, error) {
	resp, err := c.fakeChunkServer.apkChunk(ctx, req)
	c.cancel()
	return resp, err
}

func TestCleanupKeepsPartialDownloadBetweenAttempts(t *testing.T) {
	stateDir := t.TempDir()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	oldAPK := testAPKBytes(100)
	publishTestManifest(t, stateDir, testAPKRef(t, oldAPK, "app-v1.apk", time.Now().Add(time.Hour)), oldAPK)
	apk := testAPKBytes(apkChunkSize + 1234)
	ref := testAPKRef(t, apk, "app-v2.apk", time.Now().Add(time.Hour))
	ctx, cancel := context.WithCancel(t.Context())
	server := &cancellingChunkServer{fakeChunkServer: fakeChunkServer{apk: apk}, cancel: cancel}
	d := &apkDownloader{}
	d.handle(ctx, envConfig{StateDir: stateDir}, server, "w1", ref)
	d.wait()
	part := filepath.Join(twDir, apkTmpDir, ref.APKSHA256+".part")
	if info, err := os.Stat(part); err != nil || info.Size() != apkChunkSize {
		t.Fatalf("first attempt did not leave a partial download: %v", err)
	}
	if err := cleanupDistributedAPKs(stateDir, d.pendingRef()); err != nil {
		t.Fatal(err)
	}
	if !fileExists(part) {
		t.Fatal("cleanup removed the partial download of the release being retried")
	}
	// The next pull hands over the same release and the download resumes.
	full := &fakeChunkServer{apk: apk}
	d.handle(t.Context(), envConfig{StateDir: stateDir}, full, "w1", ref)
	d.wait()
	if len(full.requests) == 0 || full.requests[0].Offset != apkChunkSize {
		t.Fatalf("retry did not resume: %+v", full.requests)
	}
	if !fileExists(filepath.Join(twDir, "app-v2.apk")) || fileExists(part) {
		t.Fatal("retry did not publish the apk")
	}
	if d.pendingRef() != nil {
		t.Fatal("published release still pending")
	}
}

func TestCleanupRemovesStaleWriteTemps(t *testing.T) {
	apk := testAPKBytes(100)
	ref := testAPKRef(t, apk, "app-v1.apk", time.Now().Add(time.Hour))
	for name, withManifest := range map[string]bool{"manifest": true, "no manifest": false} {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			twDir := filepath.Join(stateDir, "distributor", "tw")
			if withManifest {
				publishTestManifest(t, stateDir, ref, apk)
			}
			// Orphans of interrupted writes, old enough to be abandoned.
			stale := []string{".app-v2.apk.123.tmp", ".config.json.456.tmp", filepath.Join(apkTmpDir, "old.part")}
			// A write still in progress is recent; the published files stay
			// however old they are.
			kept := []string{".app-v3.apk.789.tmp", "config.json", "config.json.minisig", "endpoints.json", "endpoints.json.minisig", "version.json", "keep.txt"}
			if withManifest {
				kept = append(kept, "app-v1.apk", "update-manifest.json", "update-manifest.json.minisig")
			} else {
				// Without a manifest nothing says which APK is current.
				kept = append(kept, "other.apk")
			}
			for _, name := range append(append([]string{}, stale...), kept...) {
				if !fileExists(filepath.Join(twDir, name)) {
					if err := writeFile(filepath.Join(twDir, name), []byte("x"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if name != ".app-v3.apk.789.tmp" {
					old := time.Now().Add(-time.Hour)
					if err := os.Chtimes(filepath.Join(twDir, name), old, old); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := cleanupDistributedAPKs(stateDir, nil); err != nil {
				t.Fatal(err)
			}
			for _, name := range stale {
				if fileExists(filepath.Join(twDir, name)) {
					t.Errorf("%s not cleaned up", name)
				}
			}
			for _, name := range kept {
				if !fileExists(filepath.Join(twDir, name)) {
					t.Errorf("cleanup removed %s", name)
				}
			}
		})
	}
}
