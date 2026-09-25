package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aead.dev/minisign"
	"github.com/flynn/noise"

	"github.com/TrafficWrapper/worker/agent/internal/protocol"
)

const orchestratorPrologue = "TrafficWrapper orchestrator worker v1"

type orchState struct {
	WorkerID         string `json:"worker_id"`
	Status           string `json:"status"`
	SignerPublicKey  string `json:"signer_public_key"`
	AppliedSeq       int64  `json:"applied_seq"`
	ClientAppliedSeq int64  `json:"client_applied_seq,omitempty"`
}

type orchStartRequest struct {
	Message string `json:"message"`
}

type orchStartResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	SID     string `json:"sid,omitempty"`
	Message string `json:"message,omitempty"`
}

type orchEnvelope struct {
	SID     string `json:"sid"`
	Message string `json:"message"`
	Payload string `json:"payload"`
}

type orchEnvelopeResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Payload string `json:"payload,omitempty"`
}

type orchEnrollRequest struct {
	Token           string         `json:"token"`
	WorkerStaticPub string         `json:"worker_static_pub"`
	SelfDescribe    map[string]any `json:"self_describe"`
}

type orchEnrollResponse struct {
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
	WorkerID        string `json:"worker_id,omitempty"`
	Status          string `json:"status,omitempty"`
	SignerPublicKey string `json:"signer_public_key,omitempty"`
}

type orchPullRequest struct {
	WorkerID           string   `json:"worker_id"`
	HaveSeq            int64    `json:"have_seq"`
	WorkerCapabilities []string `json:"worker_capabilities,omitempty"`
}

type orchPullResponse struct {
	OK           bool                `json:"ok"`
	Error        string              `json:"error,omitempty"`
	Status       string              `json:"status,omitempty"`
	WorkerID     string              `json:"worker_id,omitempty"`
	DesiredSeq   int64               `json:"desired_seq,omitempty"`
	NotModified  bool                `json:"not_modified,omitempty"`
	WorkerBundle orchSignedConfig    `json:"worker_bundle,omitempty"`
	ClientBundle orchSignedConfig    `json:"client_bundle,omitempty"`
	Update       *orchUpdateArtifact `json:"update,omitempty"`
}

type orchAckRequest struct {
	WorkerID         string            `json:"worker_id"`
	AppliedVersion   int64             `json:"applied_version"`
	SelfCheck        string            `json:"self_check"`
	EgressIPObserved string            `json:"egress_ip_observed"`
	SelfDescribe     map[string]any    `json:"self_describe,omitempty"`
	Usage            []orchUsageReport `json:"usage,omitempty"`
}

type orchNudgeRequest struct {
	WorkerID     string         `json:"worker_id"`
	HaveSeq      int64          `json:"have_seq"`
	SelfDescribe map[string]any `json:"self_describe,omitempty"`
}

type orchTelemetryRequest struct {
	WorkerID      string            `json:"worker_id"`
	PayloadBase64 string            `json:"payload_base64"`
	Headers       map[string]string `json:"headers,omitempty"`
	ReceivedAt    string            `json:"received_at"`
}

type orchNudgeResponse struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	DesiredSeq int64  `json:"desired_seq,omitempty"`
	Heartbeat  bool   `json:"heartbeat,omitempty"`
}

type orchAckResponse struct {
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	DesiredSeq    int64  `json:"desired_seq,omitempty"`
	AppliedSeq    int64  `json:"applied_seq,omitempty"`
	EgressIPProbe string `json:"egress_ip_probe,omitempty"`
	EgressMatch   bool   `json:"egress_match"`
	QuotaBlocks   int    `json:"quota_blocks,omitempty"`
}

type orchUsageReport struct {
	DeviceID     string `json:"device_id,omitempty"`
	AWGPublicKey string `json:"awg_public_key,omitempty"`
	Source       string `json:"source,omitempty"`
	RxBytes      uint64 `json:"rx_bytes,omitempty"`
	TxBytes      uint64 `json:"tx_bytes,omitempty"`
}

type orchSignedConfig struct {
	ConfigJSON string `json:"config_json,omitempty"`
	Minisig    string `json:"minisig,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
}

type orchUpdateArtifact struct {
	ManifestJSON    string `json:"manifest_json,omitempty"`
	ManifestMinisig string `json:"manifest_minisig,omitempty"`
	APKName         string `json:"apk_name,omitempty"`
	APKSHA256       string `json:"apk_sha256,omitempty"`
	APKBase64       string `json:"apk_base64,omitempty"`
}

// prepareOrchestrator validates the orchestrator settings up front so a
// misconfigured worker exits with a clear error instead of running a silently
// disabled orchestrator loop.
func prepareOrchestrator(cfg envConfig, st stateFile) (*orchClient, error) {
	client, err := newOrchClient(cfg, st)
	if err != nil {
		return nil, fmt.Errorf("orchestrator client: %w", err)
	}
	if loadOrchState(cfg.StateDir).WorkerID == "" && strings.TrimSpace(cfg.EnrollToken) == "" {
		return nil, errors.New("worker is not enrolled and ENROLL_TOKEN is empty")
	}
	return client, nil
}

const (
	orchBackoffMin = time.Second
	orchBackoffMax = time.Minute
	// orchMinHeartbeatInterval keeps a nudge endpoint that answers instantly
	// (no long-poll) from turning the loop into a busy loop.
	orchMinHeartbeatInterval = 5 * time.Second
	// orchForcedPullInterval re-checks the config even when nudges keep
	// reporting nothing new.
	orchForcedPullInterval = 10 * time.Minute
)

// backoff is an exponential delay with full jitter, reset after success.
type backoff struct {
	min, max, current time.Duration
}

func newBackoff(min, max time.Duration) *backoff {
	return &backoff{min: min, max: max}
}

func (b *backoff) next() time.Duration {
	if b.current == 0 {
		b.current = b.min
	} else {
		b.current *= 2
		if b.current > b.max {
			b.current = b.max
		}
	}
	return b.current/2 + time.Duration(mathrand.Int64N(int64(b.current/2)+1))
}

func (b *backoff) reset() {
	b.current = 0
}

func runOrchestratorLoop(ctx context.Context, cfg envConfig, st stateFile, client *orchClient) {
	state := loadOrchState(cfg.StateDir)
	orchAppliedSeqGauge.Store(state.AppliedSeq)
	retry := newBackoff(orchBackoffMin, orchBackoffMax)
	var lastAck, lastPull time.Time
	pullNeeded := true
	for ctx.Err() == nil {
		if state.WorkerID == "" {
			resp, err := client.enroll(ctx, cfg.EnrollToken, selfDescribe(cfg, st))
			recordOrchRequest("enroll", err)
			if err != nil {
				slog.Warn("orch enroll failed", "err", err)
				sleepCtx(ctx, retry.next())
				continue
			}
			state.WorkerID = resp.WorkerID
			state.Status = resp.Status
			state.SignerPublicKey = resp.SignerPublicKey
			_ = saveOrchState(cfg.StateDir, state)
			slog.Info("orch enroll", "status", state.Status, "worker_id", state.WorkerID)
		}
		if pullNeeded || time.Since(lastPull) >= orchForcedPullInterval {
			pull, err := client.pull(ctx, state.WorkerID, state.AppliedSeq)
			recordOrchRequest("pull", err)
			if err != nil {
				slog.Warn("orch pull failed", "err", err)
				sleepCtx(ctx, retry.next())
				continue
			}
			lastPull = time.Now()
			if pull.DesiredSeq > 0 {
				orchDesiredSeqGauge.Store(pull.DesiredSeq)
			}
			if !pull.OK {
				state.Status = pull.Status
				_ = saveOrchState(cfg.StateDir, state)
				slog.Warn("orch pull pending/error", "status", pull.Status, "error", pull.Error)
				sleepCtx(ctx, retry.next())
				continue
			}
			state.Status = pull.Status
			if !pull.NotModified {
				started := time.Now()
				seq, clientSeq, err := applyOrchBundles(cfg, st, state, pull.WorkerBundle, pull.ClientBundle, pull.Update)
				applyDurationMillis.Store(time.Since(started).Milliseconds())
				if err != nil {
					slog.Error("orch apply rejected", "err", err)
					sleepCtx(ctx, retry.next())
					continue
				}
				state.AppliedSeq = seq
				state.ClientAppliedSeq = clientSeq
				_ = saveOrchState(cfg.StateDir, state)
				orchAppliedSeqGauge.Store(seq)
				if orchDesiredSeqGauge.Load() < seq {
					orchDesiredSeqGauge.Store(seq)
				}
				slog.Info("orch applied", "seq", seq, "duration", time.Since(started).Round(time.Millisecond))
				reportOrchAck(ctx, client, cfg, st, state.WorkerID, seq)
				lastAck = time.Now()
				retry.reset()
				continue
			}
			_ = saveOrchState(cfg.StateDir, state)
			pullNeeded = false
			retry.reset()
		}
		started := time.Now()
		nudge, err := client.nudge(ctx, state.WorkerID, state.AppliedSeq, selfDescribe(cfg, st))
		recordOrchRequest("nudge", err)
		if err != nil {
			slog.Warn("orch nudge failed", "err", err)
			pullNeeded = true
			sleepCtx(ctx, retry.next())
			continue
		}
		retry.reset()
		if nudge.DesiredSeq > 0 {
			orchDesiredSeqGauge.Store(nudge.DesiredSeq)
		}
		if nudge.DesiredSeq > state.AppliedSeq {
			pullNeeded = true
		} else {
			slog.Debug("orch nudge heartbeat", "desired", nudge.DesiredSeq, "applied", state.AppliedSeq)
		}
		if time.Since(lastAck) >= cfg.OrchAckInterval {
			reportOrchAck(ctx, client, cfg, st, state.WorkerID, state.AppliedSeq)
			reconcileStarted := time.Now()
			if err := reconcileAWGPeers(cfg, st); err != nil {
				slog.Warn("awg periodic reconcile incomplete", "err", err)
			}
			awgReconcileMillisTotal.Add(time.Since(reconcileStarted).Milliseconds())
			lastAck = time.Now()
		}
		if !pullNeeded {
			if elapsed := time.Since(started); elapsed < orchMinHeartbeatInterval {
				sleepCtx(ctx, orchMinHeartbeatInterval-elapsed)
			}
		}
	}
}

func reportOrchAck(ctx context.Context, client *orchClient, cfg envConfig, st stateFile, workerID string, seq int64) {
	devices := cachedApprovedDevices(cfg.StateDir)
	approvedDevicesGauge.Store(int64(len(filterUnexpiredApprovedDevices(devices, time.Now().UTC()))))
	usage := collectWorkerUsageReports(cfg, devices)
	ack, err := client.ack(ctx, workerID, seq, cfg.EgressIP, selfDescribe(cfg, st), usage)
	recordOrchRequest("ack", err)
	if err != nil {
		slog.Warn("orch ack failed", "err", err)
		return
	}
	if ack.QuotaBlocks > 0 {
		quotaBlocksTotal.Add(uint64(ack.QuotaBlocks))
	}
	if ack.DesiredSeq > 0 {
		orchDesiredSeqGauge.Store(ack.DesiredSeq)
	}
	slog.Debug("orch ack ok", "applied", ack.AppliedSeq, "desired", ack.DesiredSeq, "egress_probe", ack.EgressIPProbe, "match", ack.EgressMatch)
	if !ack.EgressMatch && ack.EgressIPProbe != "" {
		slog.Warn("orch reports egress mismatch", "observed", ack.EgressIPProbe, "configured", cfg.EgressIP)
	}
}

func collectWorkerUsageReports(cfg envConfig, devices []approvedDevice) []orchUsageReport {
	usage, err := collectAWGUsageReports(cfg, devices)
	if err != nil {
		slog.Warn("awg usage report skipped", "err", err)
	}
	reality, err := collectRealityUsageReports(cfg, devices)
	if err != nil {
		slog.Warn("reality usage report skipped", "err", err)
	} else {
		usage = append(usage, reality...)
	}
	return usage
}

type orchClient struct {
	cfg       envConfig
	staticKey noise.DHKey
	serverPub []byte
	http      *http.Client
}

func newOrchClient(cfg envConfig, st stateFile) (*orchClient, error) {
	key, err := protocol.DecodeKeyPair(st.NoiseStatic.PrivateKey, st.NoiseStatic.PublicKey)
	if err != nil {
		return nil, err
	}
	serverPub, err := protocol.DecodeKeyBase64(cfg.OrchStaticPublic)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.OrchInsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // dev self-signed ORCH only.
	}
	return &orchClient{cfg: cfg, staticKey: key, serverPub: serverPub, http: &http.Client{Transport: tr, Timeout: 35 * time.Second}}, nil
}

func (c *orchClient) enroll(ctx context.Context, token string, self map[string]any) (orchEnrollResponse, error) {
	var resp orchEnrollResponse
	err := c.noiseCall(ctx, "/w/v1/enroll", orchEnrollRequest{Token: token, WorkerStaticPub: protocol.KeyToBase64(c.staticKey.Public), SelfDescribe: self}, &resp)
	return resp, err
}

func (c *orchClient) pull(ctx context.Context, workerID string, have int64) (orchPullResponse, error) {
	var resp orchPullResponse
	err := c.noiseCall(ctx, "/w/v1/config/pull", orchPullRequest{WorkerID: workerID, HaveSeq: have, WorkerCapabilities: workerCapabilities}, &resp)
	return resp, err
}

func (c *orchClient) ack(ctx context.Context, workerID string, seq int64, egressIP string, self map[string]any, usage []orchUsageReport) (orchAckResponse, error) {
	var resp orchAckResponse
	err := c.noiseCall(ctx, "/w/v1/ack", orchAckRequest{WorkerID: workerID, AppliedVersion: seq, SelfCheck: selfCheckStatus(), EgressIPObserved: egressIP, SelfDescribe: self, Usage: usage}, &resp)
	return resp, err
}

func (c *orchClient) nudge(ctx context.Context, workerID string, have int64, self map[string]any) (orchNudgeResponse, error) {
	var resp orchNudgeResponse
	err := c.noiseCall(ctx, "/w/v1/nudge/wait", orchNudgeRequest{WorkerID: workerID, HaveSeq: have, SelfDescribe: self}, &resp)
	return resp, err
}

func (c *orchClient) telemetry(ctx context.Context, workerID string, payload []byte, headers map[string]string) error {
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	err := c.noiseCall(ctx, "/w/v1/telemetry", orchTelemetryRequest{
		WorkerID:      workerID,
		PayloadBase64: base64.StdEncoding.EncodeToString(payload),
		Headers:       headers,
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}, &resp)
	if err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	return nil
}

func (c *orchClient) noiseCall(ctx context.Context, path string, req any, resp any) error {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   protocol.CipherSuite(),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		Prologue:      []byte(orchestratorPrologue),
		StaticKeypair: c.staticKey,
		PeerStatic:    c.serverPub,
	})
	if err != nil {
		return err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	var start orchStartResponse
	if err := c.postJSON(ctx, "/w/v1/handshake/start", orchStartRequest{Message: base64.StdEncoding.EncodeToString(msg1)}, &start); err != nil {
		return err
	}
	if !start.OK {
		return errors.New(start.Error)
	}
	msg2, err := base64.StdEncoding.DecodeString(start.Message)
	if err != nil {
		return err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		return err
	}
	msg3, sendCipher, recvCipher, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	payload, err := protocol.EncryptJSON(sendCipher, req)
	if err != nil {
		return err
	}
	var envResp orchEnvelopeResponse
	if err := c.postJSON(ctx, path, orchEnvelope{SID: start.SID, Message: base64.StdEncoding.EncodeToString(msg3), Payload: base64.StdEncoding.EncodeToString(payload)}, &envResp); err != nil {
		return err
	}
	if !envResp.OK {
		return errors.New(envResp.Error)
	}
	encrypted, err := base64.StdEncoding.DecodeString(envResp.Payload)
	if err != nil {
		return err
	}
	return protocol.DecryptJSON(recvCipher, encrypted, resp)
}

func (c *orchClient) postJSON(ctx context.Context, path string, req any, resp any) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.OrchURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		return fmt.Errorf("http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Decode straight from the stream: pull responses can carry an APK, and
	// buffering the raw body first would hold one more full copy in memory.
	limited := &io.LimitedReader{R: httpResp.Body, N: maxOrchResponseBytes + 1}
	if err := json.NewDecoder(limited).Decode(resp); err != nil {
		if limited.N <= 0 {
			return fmt.Errorf("orchestrator response exceeds %d bytes", maxOrchResponseBytes)
		}
		return err
	}
	return nil
}

const maxOrchResponseBytes = 128 << 20

func applyOrchBundles(cfg envConfig, st stateFile, state orchState, workerBundle, clientBundle orchSignedConfig, update *orchUpdateArtifact) (int64, int64, error) {
	seq, err := verifyOrchBundle(workerBundle, state.SignerPublicKey, state.AppliedSeq, "worker-config-v1")
	if err != nil {
		return 0, 0, err
	}
	clientSeq := state.ClientAppliedSeq
	clientBundleOK := false
	if nextClientSeq, err := verifyOrchBundleAllowEqual(clientBundle, state.SignerPublicKey, state.ClientAppliedSeq, "client-config-v1"); err != nil {
		slog.Warn("client bundle apply skipped", "err", err)
	} else {
		clientSeq = nextClientSeq
		clientBundleOK = true
	}
	if err := writeFile(filepath.Join(cfg.StateDir, "orch", "worker-config.json"), []byte(workerBundle.ConfigJSON+"\n"), 0o600); err != nil {
		return 0, 0, err
	}
	if err := writeFile(filepath.Join(cfg.StateDir, "orch", "worker-config.minisig"), []byte(workerBundle.Minisig), 0o600); err != nil {
		return 0, 0, err
	}
	if clientBundleOK {
		if err := writeFile(filepath.Join(cfg.StateDir, "distributor", "tw", "config.json"), []byte(clientBundle.ConfigJSON+"\n"), 0o644); err != nil {
			return 0, 0, err
		}
		if err := writeFile(filepath.Join(cfg.StateDir, "distributor", "tw", "config.json.minisig"), []byte(clientBundle.Minisig), 0o644); err != nil {
			return 0, 0, err
		}
	}
	if update != nil {
		if err := writeUpdateArtifact(cfg, update); err != nil {
			return 0, 0, err
		}
	}
	if err := materializeApprovedDevices(cfg, st, workerBundle.ConfigJSON); err != nil {
		return 0, 0, err
	}
	version := map[string]any{"version": fmt.Sprintf("orch-v%d", seq), "config_seq": seq, "created_at": time.Now().UTC().Format(time.RFC3339)}
	if apk := distributedAPKInfo(cfg.StateDir); len(apk) > 0 {
		version["distributed_apk"] = apk
		for key, value := range apk {
			version[key] = value
		}
	}
	if err := writeJSONFile(filepath.Join(cfg.StateDir, "distributor", "tw", "version.json"), version, 0o644); err != nil {
		return 0, 0, err
	}
	return seq, clientSeq, nil
}

func writeUpdateArtifact(cfg envConfig, update *orchUpdateArtifact) error {
	if strings.TrimSpace(update.ManifestJSON) == "" || strings.TrimSpace(update.ManifestMinisig) == "" || strings.TrimSpace(update.APKBase64) == "" {
		return errors.New("update artifact is incomplete")
	}
	apkName := filepath.Base(strings.TrimSpace(update.APKName))
	if apkName == "." || apkName == "/" || apkName == "" {
		return errors.New("update artifact apk_name is empty")
	}
	apkRaw, err := base64.StdEncoding.DecodeString(update.APKBase64)
	if err != nil {
		return err
	}
	update.APKBase64 = ""
	// The APK must match the hash inside the signed manifest that clients
	// verify; otherwise a manifest and an unrelated APK could be published
	// together.
	apkSHA := sha256HexBytes(apkRaw)
	manifestSHA, err := updateManifestAPKSHA256(update.ManifestJSON)
	if err != nil {
		return err
	}
	if apkSHA != manifestSHA {
		return errors.New("update artifact sha does not match manifest")
	}
	if declared := strings.ToLower(strings.TrimSpace(update.APKSHA256)); declared != "" && declared != apkSHA {
		return errors.New("update artifact sha mismatch")
	}
	twDir := filepath.Join(cfg.StateDir, "distributor", "tw")
	if err := writeFile(filepath.Join(twDir, "update-manifest.json"), []byte(strings.TrimSpace(update.ManifestJSON)), 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(twDir, "update-manifest.json.minisig"), []byte(strings.TrimSpace(update.ManifestMinisig)), 0o644); err != nil {
		return err
	}
	return writeFile(filepath.Join(twDir, apkName), apkRaw, 0o644)
}

func updateManifestAPKSHA256(manifestJSON string) (string, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(manifestJSON), &root); err != nil {
		return "", fmt.Errorf("parse update manifest: %w", err)
	}
	if nested, ok := root["distributed_apk"].(map[string]any); ok {
		root = nested
	}
	sha := strings.ToLower(stringFromAny(root["apk_sha256"]))
	if len(sha) != 64 {
		return "", errors.New("update manifest has no apk_sha256")
	}
	return sha, nil
}

func verifyOrchBundle(bundle orchSignedConfig, pinnedPublicKey string, maxSeen int64, expectedNS string) (int64, error) {
	return verifyOrchBundleSeq(bundle, pinnedPublicKey, maxSeen, expectedNS, false)
}

func verifyOrchBundleAllowEqual(bundle orchSignedConfig, pinnedPublicKey string, maxSeen int64, expectedNS string) (int64, error) {
	return verifyOrchBundleSeq(bundle, pinnedPublicKey, maxSeen, expectedNS, true)
}

func verifyOrchBundleSeq(bundle orchSignedConfig, pinnedPublicKey string, maxSeen int64, expectedNS string, allowEqual bool) (int64, error) {
	if strings.TrimSpace(bundle.ConfigJSON) == "" || strings.TrimSpace(bundle.Minisig) == "" {
		return 0, errors.New("bundle is empty or unsigned")
	}
	if bundle.PublicKey != pinnedPublicKey {
		return 0, errors.New("bundle signer public key mismatch")
	}
	var pub minisign.PublicKey
	if err := pub.UnmarshalText([]byte(bundle.PublicKey)); err != nil {
		return 0, errors.New("invalid signer public key")
	}
	if !minisign.Verify(pub, []byte(bundle.ConfigJSON), []byte(bundle.Minisig)) {
		return 0, errors.New("invalid bundle signature")
	}
	var meta struct {
		Namespace string `json:"ns"`
		Seq       int64  `json:"seq"`
	}
	if err := json.Unmarshal([]byte(bundle.ConfigJSON), &meta); err != nil {
		return 0, err
	}
	if meta.Namespace != expectedNS {
		return 0, fmt.Errorf("unexpected bundle namespace %q", meta.Namespace)
	}
	if allowEqual {
		if meta.Seq < maxSeen {
			return 0, fmt.Errorf("bundle rollback: seq=%d max_seen=%d", meta.Seq, maxSeen)
		}
		return meta.Seq, nil
	}
	if meta.Seq <= maxSeen {
		return 0, fmt.Errorf("bundle rollback: seq=%d max_seen=%d", meta.Seq, maxSeen)
	}
	return meta.Seq, nil
}

func loadOrchState(stateDir string) orchState {
	raw, err := os.ReadFile(filepath.Join(stateDir, "orch", "state.json"))
	if err != nil {
		return orchState{}
	}
	var state orchState
	_ = json.Unmarshal(raw, &state)
	return state
}

func saveOrchState(stateDir string, state orchState) error {
	return writeJSONFile(filepath.Join(stateDir, "orch", "state.json"), state, 0o600)
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
