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
	"log"
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
	WorkerID        string `json:"worker_id"`
	Status          string `json:"status"`
	SignerPublicKey string `json:"signer_public_key"`
	AppliedSeq      int64  `json:"applied_seq"`
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
	WorkerID string `json:"worker_id"`
	HaveSeq  int64  `json:"have_seq"`
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

func runOrchestratorLoop(ctx context.Context, cfg envConfig, st stateFile) {
	if cfg.OrchStaticPublic == "" {
		log.Printf("orch disabled: ORCH_STATIC_PUBLIC_KEY is empty")
		return
	}
	client, err := newOrchClient(cfg, st)
	if err != nil {
		log.Printf("orch client init failed: %v", err)
		return
	}
	state := loadOrchState(cfg.StateDir)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if state.WorkerID == "" {
			if cfg.EnrollToken == "" {
				log.Printf("orch enroll skipped: ENROLL_TOKEN is empty")
				return
			}
			resp, err := client.enroll(cfg.EnrollToken, selfDescribe(cfg, st))
			if err != nil {
				log.Printf("orch enroll failed: %v", err)
				sleepCtx(ctx, 5*time.Second)
				continue
			}
			state.WorkerID = resp.WorkerID
			state.Status = resp.Status
			state.SignerPublicKey = resp.SignerPublicKey
			_ = saveOrchState(cfg.StateDir, state)
			log.Printf("orch enroll status=%s worker_id=%s", state.Status, state.WorkerID)
		}
		pull, err := client.pull(state.WorkerID, state.AppliedSeq)
		if err != nil {
			log.Printf("orch pull failed: %v", err)
			sleepCtx(ctx, 5*time.Second)
			continue
		}
		if !pull.OK {
			state.Status = pull.Status
			_ = saveOrchState(cfg.StateDir, state)
			log.Printf("orch pull pending/error status=%s error=%s", pull.Status, pull.Error)
			sleepCtx(ctx, 3*time.Second)
			continue
		}
		state.Status = pull.Status
		if pull.NotModified {
			_ = saveOrchState(cfg.StateDir, state)
			nudge, err := client.nudge(state.WorkerID, state.AppliedSeq, selfDescribe(cfg, st))
			if err != nil {
				log.Printf("orch nudge failed: %v", err)
				sleepCtx(ctx, 5*time.Second)
			} else if nudge.DesiredSeq <= state.AppliedSeq {
				log.Printf("orch nudge heartbeat desired=%d applied=%d", nudge.DesiredSeq, state.AppliedSeq)
			}
			reportOrchAck(client, cfg, st, state.WorkerID, state.AppliedSeq)
			continue
		}
		seq, err := applyOrchBundles(cfg, st, state, pull.WorkerBundle, pull.ClientBundle, pull.Update)
		if err != nil {
			log.Printf("orch apply rejected: %v", err)
			sleepCtx(ctx, 5*time.Second)
			continue
		}
		state.AppliedSeq = seq
		_ = saveOrchState(cfg.StateDir, state)
		reportOrchAck(client, cfg, st, state.WorkerID, seq)
		sleepCtx(ctx, 5*time.Second)
	}
}

func reportOrchAck(client *orchClient, cfg envConfig, st stateFile, workerID string, seq int64) {
	usage, err := collectAWGUsageReports(cfg, cachedApprovedDevices(cfg.StateDir))
	if err != nil {
		log.Printf("awg usage report skipped: %v", err)
	}
	ack, err := client.ack(workerID, seq, cfg.EgressIP, selfDescribe(cfg, st), usage)
	if err != nil {
		log.Printf("orch ack failed: %v", err)
		return
	}
	if ack.QuotaBlocks > 0 {
		quotaBlocksTotal.Add(uint64(ack.QuotaBlocks))
	}
	log.Printf("orch ack ok applied=%d desired=%d egress_probe=%s match=%t", ack.AppliedSeq, ack.DesiredSeq, ack.EgressIPProbe, ack.EgressMatch)
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

func (c *orchClient) enroll(token string, self map[string]any) (orchEnrollResponse, error) {
	var resp orchEnrollResponse
	err := c.noiseCall("/w/v1/enroll", orchEnrollRequest{Token: token, WorkerStaticPub: protocol.KeyToBase64(c.staticKey.Public), SelfDescribe: self}, &resp)
	return resp, err
}

func (c *orchClient) pull(workerID string, have int64) (orchPullResponse, error) {
	var resp orchPullResponse
	err := c.noiseCall("/w/v1/config/pull", orchPullRequest{WorkerID: workerID, HaveSeq: have}, &resp)
	return resp, err
}

func (c *orchClient) ack(workerID string, seq int64, egressIP string, self map[string]any, usage []orchUsageReport) (orchAckResponse, error) {
	var resp orchAckResponse
	err := c.noiseCall("/w/v1/ack", orchAckRequest{WorkerID: workerID, AppliedVersion: seq, SelfCheck: "ok", EgressIPObserved: egressIP, SelfDescribe: self, Usage: usage}, &resp)
	return resp, err
}

func (c *orchClient) nudge(workerID string, have int64, self map[string]any) (orchNudgeResponse, error) {
	var resp orchNudgeResponse
	err := c.noiseCall("/w/v1/nudge/wait", orchNudgeRequest{WorkerID: workerID, HaveSeq: have, SelfDescribe: self}, &resp)
	return resp, err
}

func (c *orchClient) telemetry(workerID string, payload []byte, headers map[string]string) error {
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	err := c.noiseCall("/w/v1/telemetry", orchTelemetryRequest{
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

func (c *orchClient) noiseCall(path string, req any, resp any) error {
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
	if err := c.postJSON("/w/v1/handshake/start", orchStartRequest{Message: base64.StdEncoding.EncodeToString(msg1)}, &start); err != nil {
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
	if err := c.postJSON(path, orchEnvelope{SID: start.SID, Message: base64.StdEncoding.EncodeToString(msg3), Payload: base64.StdEncoding.EncodeToString(payload)}, &envResp); err != nil {
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

func (c *orchClient) postJSON(path string, req any, resp any) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpResp, err := c.http.Post(strings.TrimRight(c.cfg.OrchURL, "/")+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(httpResp.Body, maxOrchResponseBytes))
	if httpResp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, resp)
}

const maxOrchResponseBytes = 128 << 20

func applyOrchBundles(cfg envConfig, st stateFile, state orchState, workerBundle, clientBundle orchSignedConfig, update *orchUpdateArtifact) (int64, error) {
	seq, err := verifyOrchBundle(workerBundle, state.SignerPublicKey, state.AppliedSeq, "worker-config-v1")
	if err != nil {
		return 0, err
	}
	if _, err := verifyOrchBundle(clientBundle, state.SignerPublicKey, 0, "client-config-v1"); err != nil {
		return 0, err
	}
	if err := writeFile(filepath.Join(cfg.StateDir, "orch", "worker-config.json"), []byte(workerBundle.ConfigJSON+"\n"), 0o600); err != nil {
		return 0, err
	}
	if err := writeFile(filepath.Join(cfg.StateDir, "orch", "worker-config.minisig"), []byte(workerBundle.Minisig), 0o600); err != nil {
		return 0, err
	}
	if err := writeFile(filepath.Join(cfg.StateDir, "distributor", "tw", "config.json"), []byte(clientBundle.ConfigJSON+"\n"), 0o644); err != nil {
		return 0, err
	}
	if err := writeFile(filepath.Join(cfg.StateDir, "distributor", "tw", "config.json.minisig"), []byte(clientBundle.Minisig), 0o644); err != nil {
		return 0, err
	}
	if update != nil {
		if err := writeUpdateArtifact(cfg, update); err != nil {
			return 0, err
		}
	}
	if err := materializeApprovedDevices(cfg, st, workerBundle.ConfigJSON); err != nil {
		return 0, err
	}
	version := map[string]any{"version": fmt.Sprintf("orch-v%d", seq), "config_seq": seq, "created_at": time.Now().UTC().Format(time.RFC3339)}
	if apk := distributedAPKInfo(cfg.StateDir); len(apk) > 0 {
		version["distributed_apk"] = apk
		for key, value := range apk {
			version[key] = value
		}
	}
	if err := writeJSONFile(filepath.Join(cfg.StateDir, "distributor", "tw", "version.json"), version, 0o644); err != nil {
		return 0, err
	}
	return seq, nil
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
	if strings.TrimSpace(update.APKSHA256) != "" && sha256HexBytes(apkRaw) != strings.ToLower(strings.TrimSpace(update.APKSHA256)) {
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

func verifyOrchBundle(bundle orchSignedConfig, pinnedPublicKey string, maxSeen int64, expectedNS string) (int64, error) {
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
