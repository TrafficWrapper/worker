package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHeartbeatContinuesWhilePullFails(t *testing.T) {
	f := newFakeOrchestrator(t, func(path string, _ json.RawMessage) any {
		switch {
		case strings.HasSuffix(path, "/config/pull"):
			return map[string]any{"ok": false, "status": "active", "error": "signer unavailable"}
		case strings.HasSuffix(path, "/nudge/wait"):
			return map[string]any{"ok": true, "desired_seq": 1}
		default:
			return map[string]any{"ok": true}
		}
	})
	cfg := envConfig{StateDir: t.TempDir(), OrchAckInterval: 10 * time.Millisecond}
	if err := saveOrchState(cfg.StateDir, orchState{WorkerID: "w1", AppliedSeq: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	runOrchestratorLoop(ctx, cfg, hardeningTestState(), f.client(cfg))
	pulls, nudges, acks := len(f.requestsTo("/w/v1/config/pull")), len(f.requestsTo("/w/v1/nudge/wait")), len(f.requestsTo("/w/v1/ack"))
	if nudges == 0 || acks == 0 {
		t.Fatalf("heartbeat stopped while pulls fail: pulls=%d nudges=%d acks=%d", pulls, nudges, acks)
	}
	if pulls < 2 || pulls > 6 {
		t.Fatalf("failing pull not retried with backoff: %d pulls in 2s", pulls)
	}
}

func TestPartialApplyCommitsBundle(t *testing.T) {
	t.Cleanup(func() { setApplyIncomplete(false) })
	priv, pubText := testSigner(t)
	cfg := envConfig{
		StateDir:          t.TempDir(),
		AWGUAPISocket:     filepath.Join(t.TempDir(), "missing.sock"),
		DisableSmokePeers: true,
		RealityDest:       "www.example.net:443",
		CamouflageDomain:  "www.example.net",
	}
	state := orchState{WorkerID: "w", SignerPublicKey: pubText, AppliedSeq: 1}
	worker := signedBundleForTest(t, priv, pubText, "worker-config-v1", 2, `,"desired_state":{"approved_devices":[`+testDeviceJSON(1)+`]}`)
	client := signedBundleForTest(t, priv, pubText, "client-config-v1", 2, "")
	seq, _, err := applyOrchBundles(cfg, hardeningTestState(), state, worker, client, nil)
	var partial *partialApplyError
	if !errors.As(err, &partial) || seq != 2 {
		t.Fatalf("an unreachable AWG profile must not reject the bundle: seq=%d err=%v", seq, err)
	}
	if raw, _ := os.ReadFile(xrayConfigPath(cfg)); !strings.Contains(string(raw), "device-1") {
		t.Fatal("xray not applied because AWG failed")
	}
	setApplyIncomplete(true)
	if !strings.Contains(selfCheckStatus(), "apply") {
		t.Fatalf("self_check %q", selfCheckStatus())
	}
	if err := reapplyCachedDesiredState(cfg, hardeningTestState()); err == nil {
		t.Fatal("retry succeeded although the AWG socket is still missing")
	}
}

func TestLoopCommitsPartialApplyAndAcks(t *testing.T) {
	t.Cleanup(func() { setApplyIncomplete(false) })
	priv, pubText := testSigner(t)
	worker := signedBundleForTest(t, priv, pubText, "worker-config-v1", 2, `,"desired_state":{"approved_devices":[`+testDeviceJSON(1)+`]}`)
	client := signedBundleForTest(t, priv, pubText, "client-config-v1", 2, "")
	f := newFakeOrchestrator(t, func(path string, raw json.RawMessage) any {
		switch {
		case strings.HasSuffix(path, "/config/pull"):
			var req orchPullRequest
			_ = json.Unmarshal(raw, &req)
			if req.HaveSeq >= 2 {
				return map[string]any{"ok": true, "status": "active", "not_modified": true}
			}
			return map[string]any{"ok": true, "status": "active", "desired_seq": 2, "worker_bundle": worker, "client_bundle": client}
		case strings.HasSuffix(path, "/nudge/wait"):
			return map[string]any{"ok": true, "desired_seq": 2}
		default:
			return map[string]any{"ok": true}
		}
	})
	cfg := envConfig{
		StateDir:          t.TempDir(),
		AWGUAPISocket:     filepath.Join(t.TempDir(), "missing.sock"),
		DisableSmokePeers: true,
		RealityDest:       "www.example.net:443",
		CamouflageDomain:  "www.example.net",
		OrchAckInterval:   time.Hour,
	}
	if err := saveOrchState(cfg.StateDir, orchState{WorkerID: "w", SignerPublicKey: pubText, AppliedSeq: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	runOrchestratorLoop(ctx, cfg, hardeningTestState(), f.client(cfg))
	if got := loadOrchState(cfg.StateDir).AppliedSeq; got != 2 {
		t.Fatalf("applied seq %d, want 2", got)
	}
	acks := f.requestsTo("/w/v1/ack")
	if len(acks) == 0 || !strings.Contains(string(acks[0]), `"applied_version":2`) || !strings.Contains(string(acks[0]), "degraded: ") {
		t.Fatalf("ack after partial apply: %s", acks)
	}
	if n := len(f.requestsTo("/w/v1/config/pull")); n > 3 {
		t.Fatalf("accepted bundle pulled again %d times", n)
	}
}
