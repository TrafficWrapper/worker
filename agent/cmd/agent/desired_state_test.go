package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
)

func testDeviceJSON(i int) string {
	return fmt.Sprintf(`{"device_id":"device-%d","reality_uuid":"4fad2182-6de3-4407-bf8f-d8c68816%04d","awg_public_key":"%s","internal_ip":"10.13.13.%d/32","psk2":"%s","status":"approved"}`,
		i, i, keyB64(byte(10+i)), 10+i, keyB64(byte(100+i)))
}

func testWorkerConfig(desired string) string {
	return `{"desired_state":{` + desired + `}}`
}

func TestDesiredStateEnabledFlags(t *testing.T) {
	devices := `"approved_devices":[` + testDeviceJSON(1) + `]`
	for _, tc := range []struct {
		name                string
		extra               string
		wantReality, wantAW bool
	}{
		{"absent means on", "", true, true},
		{"reality off", `,"reality":{"enabled":false},"awg":{"enabled":true}`, false, true},
		{"awg off", `,"awg":{"enabled":false}`, true, false},
		{"both off", `,"reality":{"enabled":false},"awg":{"enabled":false}`, false, false},
	} {
		ds, err := parseDesiredState(testWorkerConfig(devices + tc.extra))
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		if got := len(ds.realityDevices(now)) == 1; got != tc.wantReality {
			t.Fatalf("%s: reality devices served=%v", tc.name, got)
		}
		if got := len(ds.awgDevices(now)) == 1; got != tc.wantAW {
			t.Fatalf("%s: awg devices served=%v", tc.name, got)
		}
	}
	revoked := desiredState{revoked: true, realityEnabled: true, awgEnabled: true, devices: []approvedDevice{{DeviceID: "x"}}}
	if revoked.realityDevices(time.Now()) != nil || revoked.awgDevices(time.Now()) != nil || !revoked.awgIntentionallyEmpty() {
		t.Fatal("revoked worker must serve no devices")
	}
}

func TestApplyDesiredStateHonorsDisabledProtocols(t *testing.T) {
	cfg := envConfig{StateDir: t.TempDir(), DisableSmokePeers: true, RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net"}
	st := hardeningTestState()
	ds, err := parseDesiredState(testWorkerConfig(`"approved_devices":[` + testDeviceJSON(1) + `],"reality":{"enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyDesiredState(cfg, st, ds); err != nil {
		t.Fatal(err)
	}
	xray, err := os.ReadFile(xrayConfigPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(xray), "device-1") {
		t.Fatalf("REALITY user rendered while reality is disabled:\n%s", xray)
	}
	registry, err := os.ReadFile(defaultAWGInboundProfile(cfg).registryPath(cfg.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(registry), keyB64(11)) {
		t.Fatalf("AWG peer missing while awg is enabled:\n%s", registry)
	}
}

func TestCheckRejectionsBlocksMostlyInvalidLists(t *testing.T) {
	bad := `{"device_id":"bad","reality_uuid":"nope","status":"approved"}`
	for _, tc := range []struct {
		list    []string
		wantErr bool
	}{
		{nil, false},
		{[]string{testDeviceJSON(1), testDeviceJSON(2), testDeviceJSON(3)}, false},
		{[]string{testDeviceJSON(1), testDeviceJSON(2), testDeviceJSON(3), bad}, false},
		{[]string{testDeviceJSON(1), bad, bad}, true},
		{[]string{bad}, true},
	} {
		ds, err := parseDesiredState(testWorkerConfig(`"approved_devices":[` + strings.Join(tc.list, ",") + `]`))
		if err != nil {
			t.Fatal(err)
		}
		if err := ds.checkRejections(); (err != nil) != tc.wantErr {
			t.Fatalf("%d entries, %d rejected: err=%v", ds.input, ds.rejected, err)
		}
	}
}

func testSigner(t *testing.T) (minisign.PrivateKey, string) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv, mustMarshalText(t, pub)
}

func TestApplyOrchBundlesChecksIdentityAndRejections(t *testing.T) {
	priv, pubText := testSigner(t)
	cfg := envConfig{StateDir: t.TempDir(), DisableSmokePeers: true}
	state := orchState{WorkerID: "w-self", SignerPublicKey: pubText, AppliedSeq: 1}
	client := signedBundleForTest(t, priv, pubText, "client-config-v1", 1, "")
	for name, extra := range map[string]string{
		"other worker":  `,"worker_id":"w-other","desired_state":{"approved_devices":[]}`,
		"schema 2":      `,"schema":2,"desired_state":{"approved_devices":[]}`,
		"schema string": `,"schema":"1","desired_state":{"approved_devices":[]}`,
		"all rejected":  `,"desired_state":{"approved_devices":[{"device_id":"bad","reality_uuid":"x","status":"approved"}]}`,
	} {
		bundle := signedBundleForTest(t, priv, pubText, "worker-config-v1", 2, extra)
		if _, _, err := applyOrchBundles(cfg, stateFile{}, state, bundle, client, nil); err == nil {
			t.Fatalf("%s: bundle applied", name)
		}
		if fileExists(filepath.Join(cfg.StateDir, "orch", "worker-config.json")) {
			t.Fatalf("%s: rejected bundle replaced the cached config", name)
		}
	}
	ok := signedBundleForTest(t, priv, pubText, "worker-config-v1", 2, `,"schema":1,"worker_id":"w-self","desired_state":{"approved_devices":[]}`)
	if _, _, err := applyOrchBundles(cfg, stateFile{}, state, ok, client, nil); err != nil {
		t.Fatalf("own bundle rejected: %v", err)
	}
	legacy := signedBundleForTest(t, priv, pubText, "worker-config-v1", 3, `,"desired_state":{"approved_devices":[]}`)
	state.AppliedSeq = 2
	if _, _, err := applyOrchBundles(cfg, stateFile{}, state, legacy, client, nil); err != nil {
		t.Fatalf("bundle without worker_id/schema rejected: %v", err)
	}
}

// writeSignedCache stores a worker config the way applyOrchBundles does.
func writeSignedCache(t *testing.T, stateDir string, priv minisign.PrivateKey, pubText, config string) {
	t.Helper()
	if err := saveOrchState(stateDir, orchState{WorkerID: "w", SignerPublicKey: pubText, AppliedSeq: 3}); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(stateDir, "orch", "worker-config.json"), []byte(config+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(stateDir, "orch", "worker-config.minisig"), minisign.Sign(priv, []byte(config)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileAWGPeersAppliesIntentionalEmptySet(t *testing.T) {
	priv, pubText := testSigner(t)
	for name, config := range map[string]string{
		"signed empty list": testWorkerConfig(`"approved_devices":[]`),
		"awg disabled":      testWorkerConfig(`"approved_devices":[` + testDeviceJSON(1) + `],"awg":{"enabled":false}`),
	} {
		t.Run(name, func(t *testing.T) {
			publicHex := strings.Repeat("ab", 32)
			fake := startStatefulFakeUAPI(t, []awgPeerConfig{{PublicKeyHex: publicHex, AllowedIPs: []string{"10.13.13.10/32"}}})
			stateDir := t.TempDir()
			writeSignedCache(t, stateDir, priv, pubText, config)
			cfg := envConfig{StateDir: stateDir, AWGUAPISocket: fake.socketPath, DisableSmokePeers: true}
			if err := reconcileAWGPeers(cfg, stateFile{}); err != nil {
				t.Fatalf("intentional empty set blocked: %v", err)
			}
			if _, ok := fake.peer(publicHex); ok {
				t.Fatal("peer kept although the signed config removes it")
			}
		})
	}
	t.Run("tampered empty list", func(t *testing.T) {
		publicHex := strings.Repeat("ab", 32)
		fake := startStatefulFakeUAPI(t, []awgPeerConfig{{PublicKeyHex: publicHex, AllowedIPs: []string{"10.13.13.10/32"}}})
		stateDir := t.TempDir()
		writeSignedCache(t, stateDir, priv, pubText, testWorkerConfig(`"approved_devices":[`+testDeviceJSON(1)+`]`))
		if err := os.WriteFile(filepath.Join(stateDir, "orch", "worker-config.json"), []byte(testWorkerConfig(`"approved_devices":[]`)), 0o600); err != nil {
			t.Fatal(err)
		}
		err := reconcileAWGPeers(envConfig{StateDir: stateDir, AWGUAPISocket: fake.socketPath, DisableSmokePeers: true}, stateFile{})
		if err == nil || !strings.Contains(err.Error(), "anti-wipe guard") {
			t.Fatalf("unsigned empty set not guarded: %v", err)
		}
		if _, ok := fake.peer(publicHex); !ok {
			t.Fatal("guard removed a live peer")
		}
	})
}

func TestRevokedWorkerStopsServing(t *testing.T) {
	priv, pubText := testSigner(t)
	stateDir := t.TempDir()
	writeSignedCache(t, stateDir, priv, pubText, testWorkerConfig(`"approved_devices":[`+testDeviceJSON(1)+`]`))
	twDir := filepath.Join(stateDir, "distributor", "tw")
	for _, name := range []string{"config.json", "config.json.minisig", "update-manifest.json", "app.apk", "keep.txt"} {
		if err := writeFile(filepath.Join(twDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := newFakeOrchestrator(t, func(path string, _ json.RawMessage) any {
		return map[string]any{"ok": false, "status": "revoked", "error": "worker revoked", "code": "worker_revoked"}
	})
	cfg := envConfig{StateDir: stateDir, DisableSmokePeers: true, RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net"}
	client := f.client(cfg)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runOrchestratorLoop(ctx, cfg, hardeningTestState(), client)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for loadOrchState(stateDir).Status != orchStatusRevoked || fileExists(filepath.Join(twDir, "app.apk")) {
		if time.Now().After(deadline) {
			t.Fatal("worker did not enter the revoked state")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	for _, name := range []string{"config.json", "config.json.minisig", "update-manifest.json", "app.apk"} {
		if fileExists(filepath.Join(twDir, name)) {
			t.Fatalf("%s still published after revocation", name)
		}
	}
	if !fileExists(filepath.Join(twDir, "keep.txt")) {
		t.Fatal("unrelated file removed")
	}
	xray, err := os.ReadFile(xrayConfigPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(xray), "device-1") {
		t.Fatal("REALITY user kept after revocation")
	}
	if !fileExists(filepath.Join(stateDir, "xray", "restart-request")) {
		t.Fatal("revocation did not restart Xray to end open sessions")
	}
	// A restart must not bring the users back from the cached config.
	if err := renderXray(cfg, hardeningTestState()); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(xrayConfigPath(cfg)); strings.Contains(string(raw), "device-1") {
		t.Fatal("startup render restored users on a revoked worker")
	}
	if err := renderDistributor(cfg, hardeningTestState()); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(twDir, "config.json")) {
		t.Fatal("startup render published a placeholder config on a revoked worker")
	}
	if len(f.requestsTo("/w/v1/config/pull")) != 1 {
		t.Fatalf("revoked worker kept pulling without backoff: %d pulls", len(f.requestsTo("/w/v1/config/pull")))
	}
}

func TestWorkerDeclaresRevocationCapabilities(t *testing.T) {
	for _, want := range []string{"desired_state_enabled", "revoked_status"} {
		found := false
		for _, c := range workerCapabilities {
			found = found || c == want
		}
		if !found {
			t.Fatalf("capability %q not declared: %v", want, workerCapabilities)
		}
	}
}
