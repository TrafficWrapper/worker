package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrafficWrapper/worker/core/awg/dialect"
)

func TestApprovedDevicesMaterializeToXrayAndAWGRegistry(t *testing.T) {
	cfg := envConfig{StateDir: t.TempDir(), RealityDest: "awg-gw:9443", CamouflageDomain: "example.com"}
	st := stateFile{
		SmokeRealityUUID: "14526b0e-6de3-4407-bf8f-d8c688160ce6",
		Reality:          realityState{PrivateKey: "priv", ShortID: "abcd", PublicKey: "pub"},
		AWG: awgState{
			SmokePublic:   keyB64(1),
			SmokePSK:      keyB64(2),
			SmokeIP:       "10.13.13.2/32",
			PublicKey:     keyB64(3),
			PrivateKey:    keyB64(4),
			PrivateKeyHex: strings.Repeat("0", 64),
		},
	}
	config := `{"desired_state":{"approved_devices":[{"device_id":"device-a","reality_uuid":"4fad2182-6de3-4407-bf8f-d8c688160ce6","awg_public_key":"` + keyB64(5) + `","internal_ip":"10.13.13.10/32","psk2":"` + keyB64(6) + `","status":"approved"}]}}`
	devices, err := approvedDevicesFromWorkerConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := writeXrayConfig(cfg, st, devices)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected xray config change")
	}
	xrayRaw, err := os.ReadFile(filepath.Join(cfg.StateDir, "xray", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(xrayRaw), "4fad2182-6de3-4407-bf8f-d8c688160ce6") || !strings.Contains(string(xrayRaw), st.SmokeRealityUUID) {
		t.Fatalf("xray config missing clients: %s", xrayRaw)
	}
	if strings.Contains(string(xrayRaw), "xtls-rprx-vision") {
		t.Fatalf("xray config should default to plain vless+reality without vision flow: %s", xrayRaw)
	}
	peers, err := writeAWGPeerRegistry(cfg, st, devices)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected smoke + device peers, got %d", len(peers))
	}
	raw, err := os.ReadFile(filepath.Join(cfg.StateDir, "awg", "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry awgPeerRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.Clients) != 2 || registry.Clients[1].InternalIP != "10.13.13.10/32" {
		t.Fatalf("bad awg registry: %+v", registry)
	}
}

func TestApprovedDevicesRejectIncomplete(t *testing.T) {
	_, err := approvedDevicesFromWorkerConfig(`{"desired_state":{"approved_devices":[{"device_id":"bad","status":"approved"}]}}`)
	if err == nil {
		t.Fatal("incomplete approved device accepted")
	}
}

func TestMaterializeDoesNotWriteXrayConfigWithoutRestartTarget(t *testing.T) {
	cfg := envConfig{StateDir: t.TempDir(), RealityDest: "awg-gw:9443", CamouflageDomain: "example.com"}
	st := stateFile{
		SmokeRealityUUID: "14526b0e-6de3-4407-bf8f-d8c688160ce6",
		Reality:          realityState{PrivateKey: "priv", ShortID: "abcd", PublicKey: "pub"},
		AWG: awgState{
			SmokePublic:   keyB64(1),
			SmokePSK:      keyB64(2),
			SmokeIP:       "10.13.13.2/32",
			PublicKey:     keyB64(3),
			PrivateKey:    keyB64(4),
			PrivateKeyHex: strings.Repeat("0", 64),
		},
	}
	if _, err := writeXrayConfig(cfg, st, nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(xrayConfigPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	config := `{"desired_state":{"approved_devices":[{"device_id":"device-a","reality_uuid":"4fad2182-6de3-4407-bf8f-d8c688160ce6","awg_public_key":"` + keyB64(5) + `","internal_ip":"10.13.13.10/32","psk2":"` + keyB64(6) + `","status":"approved"}]}}`
	err = materializeApprovedDevices(cfg, st, config)
	if err == nil || !strings.Contains(err.Error(), "XRAY_CONTAINER_NAME") {
		t.Fatalf("expected missing xray container error, got %v", err)
	}
	after, err := os.ReadFile(xrayConfigPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("xray config changed before restart target was available:\n%s", after)
	}
	if xrayRestartPending(cfg) {
		t.Fatal("restart pending marker should not be written before config write")
	}
}

func TestRenderXrayMarksPendingWhenStartupRestartFails(t *testing.T) {
	cfg := envConfig{
		StateDir:         t.TempDir(),
		RealityDest:      "awg-gw:9443",
		CamouflageDomain: "example.com",
		XrayContainer:    "worker-xray-1",
		DockerSocket:     filepath.Join(t.TempDir(), "docker.sock"),
	}
	st := stateFile{
		SmokeRealityUUID: "14526b0e-6de3-4407-bf8f-d8c688160ce6",
		Reality:          realityState{PrivateKey: "priv", ShortID: "abcd", PublicKey: "pub"},
		AWG: awgState{
			SmokePublic:   keyB64(1),
			SmokePSK:      keyB64(2),
			SmokeIP:       "10.13.13.2/32",
			PublicKey:     keyB64(3),
			PrivateKey:    keyB64(4),
			PrivateKeyHex: strings.Repeat("0", 64),
		},
	}
	config := `{"desired_state":{"approved_devices":[{"device_id":"device-a","reality_uuid":"4fad2182-6de3-4407-bf8f-d8c688160ce6","awg_public_key":"` + keyB64(5) + `","internal_ip":"10.13.13.10/32","psk2":"` + keyB64(6) + `","status":"approved"}]}}`
	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "orch"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.StateDir, "orch", "worker-config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	err := renderXray(cfg, st)
	if err == nil || !strings.Contains(err.Error(), "restart xray container") {
		t.Fatalf("expected startup restart error, got %v", err)
	}
	if !xrayRestartPending(cfg) {
		t.Fatal("startup restart failure did not leave pending marker")
	}
	xrayRaw, err := os.ReadFile(xrayConfigPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(xrayRaw), "4fad2182-6de3-4407-bf8f-d8c688160ce6") {
		t.Fatalf("startup xray config missing approved device: %s", xrayRaw)
	}
}

func TestSelfDescribeExposesClientRouteParameters(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, "distributor", "tw"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema":1,"ns":"apk-update-v1","version_code":11,"version_name":"0.1.10","apk_sha256":"` + strings.Repeat("a", 64) + `","apk_name":"TrafficWrapper-app-v0.1.10.apk"}`
	if err := os.WriteFile(filepath.Join(stateDir, "distributor", "tw", "update-manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := envConfig{
		StateDir:         stateDir,
		PublicAddress:    "worker.example",
		XrayPort:         2053,
		AWGPort:          51888,
		AWGSubnet:        "10.13.13.0/24",
		AWGGateway:       "10.13.13.1",
		CamouflageDomain: "www.microsoft.com",
		RealityDest:      "awg-gw:9443",
		EgressIP:         "198.51.100.8",
		DistributorURL:   "http://awg-gw:8080/tw",
	}
	st := stateFile{
		Hostname:  "worker-a",
		DialectID: "dialect-id",
		Reality:   realityState{PrivateKey: "priv", PublicKey: "reality-pub", ShortID: "short-id"},
		AWG:       awgState{PublicKey: "awg-server-pub"},
		Dialect:   dialect.Compat(),
	}
	self := selfDescribe(cfg, st)
	reality := self["reality"].(map[string]any)
	if reality["public_key"] != "reality-pub" || reality["publicKey"] != "reality-pub" {
		t.Fatalf("reality public key aliases missing: %#v", reality)
	}
	if reality["short_id"] != "short-id" || reality["shortId"] != "short-id" {
		t.Fatalf("reality short id aliases missing: %#v", reality)
	}
	if reality["server_name"] != "www.microsoft.com" || reality["serverName"] != "www.microsoft.com" {
		t.Fatalf("reality server name aliases missing: %#v", reality)
	}
	if reality["flow"] != "" {
		t.Fatalf("reality flow should default to plain vless+reality: %#v", reality)
	}
	awg := self["awg"].(map[string]any)
	if awg["public_key"] != "awg-server-pub" || awg["server_public"] != "awg-server-pub" || awg["server_public_key"] != "awg-server-pub" {
		t.Fatalf("awg server public aliases missing: %#v", awg)
	}
	if awg["address"] != "worker.example" || awg["dialect_id"] != "dialect-id" {
		t.Fatalf("awg address/dialect missing: %#v", awg)
	}
	apk := self["distributed_apk"].(map[string]any)
	if apk["version_code"] != int64(11) || apk["apk_sha256"] != strings.Repeat("a", 64) {
		t.Fatalf("distributed apk missing: %#v", apk)
	}
}

func TestDockerContainerNameCandidatesBridgeComposeV1V2(t *testing.T) {
	got := dockerContainerNameCandidates("worker_xray_1")
	want := []string{"worker_xray_1", "worker-xray-1"}
	for _, value := range want {
		if !containsString(got, value) {
			t.Fatalf("candidate %q missing from %#v", value, got)
		}
	}
	got = dockerContainerNameCandidates("worker-xray-1")
	want = []string{"worker-xray-1", "worker_xray_1"}
	for _, value := range want {
		if !containsString(got, value) {
			t.Fatalf("candidate %q missing from %#v", value, got)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func keyB64(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed
	}
	return base64.StdEncoding.EncodeToString(raw)
}
