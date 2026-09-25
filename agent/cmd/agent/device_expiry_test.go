package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInvalidExpiryFailsClosed(t *testing.T) {
	devices := []approvedDevice{
		{DeviceID: "bad", ExpiresAt: "tomorrow"},
		{DeviceID: "good", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
		{DeviceID: "none"},
	}
	got := filterUnexpiredApprovedDevices(devices, time.Now())
	if len(got) != 2 || got[0].DeviceID != "good" || got[1].DeviceID != "none" {
		t.Fatalf("devices kept: %+v", got)
	}
}

func TestExpiredSince(t *testing.T) {
	now := time.Now().UTC()
	ds := desiredState{devices: []approvedDevice{{DeviceID: "d", ExpiresAt: now.Add(-10 * time.Second).Format(time.RFC3339)}}}
	if !ds.expiredSince(now.Add(-time.Minute), now) {
		t.Fatal("expiry in the window missed")
	}
	if ds.expiredSince(now.Add(-5*time.Second), now) {
		t.Fatal("expiry before the window reported again")
	}
	ds.revoked = true
	if ds.expiredSince(now.Add(-time.Minute), now) {
		t.Fatal("revoked state reported")
	}
}

func TestLoopRemovesExpiredDeviceWithoutNewConfig(t *testing.T) {
	old := deviceExpiryCheckInterval
	deviceExpiryCheckInterval = 100 * time.Millisecond
	t.Cleanup(func() { deviceExpiryCheckInterval = old })
	priv, pubText := testSigner(t)
	stateDir := t.TempDir()
	expires := time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339)
	device := strings.Replace(testDeviceJSON(1), `"status":"approved"`, `"status":"approved","expires_at":"`+expires+`"`, 1)
	writeSignedCache(t, stateDir, priv, pubText, testWorkerConfig(`"approved_devices":[`+device+`]`))
	cfg := envConfig{StateDir: stateDir, DisableSmokePeers: true, RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net", OrchAckInterval: time.Hour}
	st := hardeningTestState()
	if err := renderXray(cfg, st); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(xrayConfigPath(cfg)); !strings.Contains(string(raw), "device-1") {
		t.Fatal("device not rendered before it expires")
	}
	f := newFakeOrchestrator(t, func(path string, _ json.RawMessage) any {
		if strings.HasSuffix(path, "/config/pull") {
			return map[string]any{"ok": true, "status": "active", "not_modified": true}
		}
		return map[string]any{"ok": true, "heartbeat": true}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runOrchestratorLoop(ctx, cfg, st, f.client(cfg))
	}()
	for {
		raw, _ := os.ReadFile(xrayConfigPath(cfg))
		if !strings.Contains(string(raw), "device-1") {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("expired device still served")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
}
