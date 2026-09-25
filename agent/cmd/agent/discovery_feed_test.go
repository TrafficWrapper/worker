package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublishDiscoveryBundle(t *testing.T) {
	stateDir := t.TempDir()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	feed := `{"schema":2,"ns":"rendezvous-v1","seq":9,"endpoints":{"awg":[],"reality":[]}}`
	if err := publishDiscoveryBundle(stateDir, orchDiscoveryBundle{EndpointsJSON: feed, EndpointsJSONMinisig: "untrusted comment: sig\nRWQ"}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(filepath.Join(twDir, "endpoints.json")); string(raw) != feed {
		t.Fatalf("feed %q", raw)
	}
	if !fileExists(filepath.Join(twDir, "endpoints.json.minisig")) {
		t.Fatal("signature not published")
	}
	for name, bad := range map[string]orchDiscoveryBundle{
		"no signature": {EndpointsJSON: feed},
		"no feed":      {EndpointsJSONMinisig: "sig"},
		"not json":     {EndpointsJSON: "<html>", EndpointsJSONMinisig: "sig"},
		"too large":    {EndpointsJSON: `"` + strings.Repeat("a", maxDiscoveryFeedBytes) + `"`, EndpointsJSONMinisig: "sig"},
	} {
		if err := publishDiscoveryBundle(stateDir, bad); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if raw, _ := os.ReadFile(filepath.Join(twDir, "endpoints.json")); string(raw) != feed {
		t.Fatal("rejected bundle replaced the published feed")
	}
}

func TestPullPublishesDiscoveryFeed(t *testing.T) {
	feed := `{"schema":2,"seq":3}`
	f := newFakeOrchestrator(t, func(path string, _ json.RawMessage) any {
		if strings.HasSuffix(path, "/config/pull") {
			return map[string]any{"ok": true, "status": "active", "not_modified": true,
				"discovery_bundle": map[string]string{"endpoints_json": feed, "endpoints_json_minisig": "sig"}}
		}
		return map[string]any{"ok": true, "heartbeat": true}
	})
	cfg := envConfig{StateDir: t.TempDir()}
	if err := saveOrchState(cfg.StateDir, orchState{WorkerID: "w1", AppliedSeq: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	runOrchestratorLoop(ctx, cfg, hardeningTestState(), f.client(cfg))
	if raw, _ := os.ReadFile(filepath.Join(cfg.StateDir, "distributor", "tw", "endpoints.json")); string(raw) != feed {
		t.Fatalf("discovery feed not published from pull: %q", raw)
	}
}

func TestRevocationRemovesDiscoveryFeed(t *testing.T) {
	stateDir := t.TempDir()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	for _, name := range []string{"endpoints.json", "endpoints.json.minisig"} {
		if err := writeFile(filepath.Join(twDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeDistributedArtifacts(stateDir); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(twDir, "endpoints.json")) || fileExists(filepath.Join(twDir, "endpoints.json.minisig")) {
		t.Fatal("revoked worker still serves the discovery feed")
	}
}
