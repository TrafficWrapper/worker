package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	if strings.Contains(string(xrayRaw), "xhttpSettings") {
		t.Fatalf("xray config should default to tcp reality without xhttp settings: %s", xrayRaw)
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

func TestAWGInboundProfilesDefaultAndJSON(t *testing.T) {
	cfg := envConfig{
		AWGPort:       51888,
		AWGSubnet:     "10.13.13.0/24",
		AWGGateway:    "10.13.13.1",
		AWGUAPISocket: "/var/run/wireguard/awg1.sock",
	}
	profiles, err := parseAWGInboundProfiles("", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Name != "awg" || profiles[0].Interface != "awg1" || profiles[0].ListenPort != awgInPort || profiles[0].PublicPort != 51888 {
		t.Fatalf("bad default profile: %+v", profiles)
	}

	raw := `[{"name":"awg","interface":"awg1","listen_port":51821,"subnet":"10.13.13.0/24","uapi_socket":"/tmp/awg1.sock"},{"name":"next","interface":"awg2","listen_port":52821,"subnet":"10.44.0.0/24","min_version_code":123}]`
	profiles, err = parseAWGInboundProfiles(raw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[1].Name != "next" || profiles[1].Gateway != "10.44.0.1" || profiles[1].UAPISocket != "/var/run/wireguard/awg2.sock" || profiles[1].PublicPort != 52821 {
		t.Fatalf("bad json profiles: %+v", profiles)
	}
}

func TestAWGInboundProfilesRejectConflicts(t *testing.T) {
	cfg := envConfig{
		AWGPort:       51888,
		AWGSubnet:     "10.13.13.0/24",
		AWGGateway:    "10.13.13.1",
		AWGUAPISocket: "/var/run/wireguard/awg1.sock",
	}
	valid := `[{"name":"awg","interface":"awg1","listen_port":51821,"subnet":"10.13.13.0/24"},{"name":"next","interface":"awg2","listen_port":52821,"subnet":"10.44.0.0/24"}]`
	if profiles, err := parseAWGInboundProfiles(valid, cfg); err != nil || len(profiles) != 2 {
		t.Fatalf("valid disjoint profiles rejected: profiles=%+v err=%v", profiles, err)
	}
	if profiles, err := parseAWGInboundProfiles("", cfg); err != nil || len(profiles) != 1 {
		t.Fatalf("default profile rejected: profiles=%+v err=%v", profiles, err)
	}

	tests := []struct {
		name      string
		raw       string
		wantError string
	}{
		{
			name:      "shared interface",
			raw:       `[{"name":"awg","interface":"awg1","listen_port":51821,"subnet":"10.13.13.0/24"},{"name":"next","interface":"awg1","listen_port":52821,"subnet":"10.44.0.0/24"}]`,
			wantError: "share interface",
		},
		{
			name:      "shared listen port",
			raw:       `[{"name":"awg","interface":"awg1","listen_port":51821,"subnet":"10.13.13.0/24"},{"name":"next","interface":"awg2","listen_port":51821,"subnet":"10.44.0.0/24"}]`,
			wantError: "share listen_port",
		},
		{
			name:      "shared uapi socket",
			raw:       `[{"name":"awg","interface":"awg1","listen_port":51821,"subnet":"10.13.13.0/24","uapi_socket":"/tmp/shared.sock"},{"name":"next","interface":"awg2","listen_port":52821,"subnet":"10.44.0.0/24","uapi_socket":"/tmp/shared.sock"}]`,
			wantError: "share uapi_socket",
		},
		{
			name:      "shared subnet",
			raw:       `[{"name":"awg","interface":"awg1","listen_port":51821,"subnet":"10.13.13.0/24"},{"name":"next","interface":"awg2","listen_port":52821,"subnet":"10.13.13.0/24"}]`,
			wantError: "share subnet",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseAWGInboundProfiles(tt.raw, cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error=%v want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestWriteAWGPeerRegistryForAdditionalProfile(t *testing.T) {
	cfg := envConfig{StateDir: t.TempDir(), AWGPort: 51888, AWGSubnet: "10.13.13.0/24", AWGGateway: "10.13.13.1", AWGUAPISocket: "/tmp/awg1.sock"}
	st := stateFile{AWG: awgState{SmokePublic: keyB64(1), SmokePSK: keyB64(2), SmokeIP: "10.13.13.2/32"}}
	profile := awgInboundProfile{Name: "next", Interface: "awg2", ListenPort: 52821, PublicPort: 52821, Subnet: "10.44.0.0/24", Gateway: "10.44.0.1", UAPISocket: "/tmp/awg2.sock"}
	devices := []approvedDevice{{
		DeviceID:     "device-a",
		AWGPublicKey: keyB64(5),
		InternalIP:   "10.13.13.10/32",
		PSK2:         keyB64(6),
		Status:       "approved",
		AWGProfiles: map[string]approvedDeviceAWGProfile{
			"next": {AWGPublicKey: keyB64(7), InternalIP: "10.44.0.10/32", PSK2: keyB64(8)},
		},
	}}
	peers, err := writeAWGPeerRegistryForProfile(cfg, st, devices, profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].PublicKey != keyB64(7) || peers[0].AllowedIP != "10.44.0.10/32" {
		t.Fatalf("bad additional profile peers: %+v", peers)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.StateDir, "awg", "profiles", "next", "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "10.13.13.10") || !strings.Contains(string(raw), "10.44.0.10") {
		t.Fatalf("additional profile registry used wrong creds: %s", raw)
	}
}

func TestApprovedDevicesRejectIncomplete(t *testing.T) {
	_, err := approvedDevicesFromWorkerConfig(`{"desired_state":{"approved_devices":[{"device_id":"bad","status":"approved"}]}}`)
	if err == nil {
		t.Fatal("incomplete approved device accepted")
	}
}

func TestSyncAWGUAPISkipsRemovalWhenDesiredSetIsIncomplete(t *testing.T) {
	staleHex := strings.Repeat("a", 64)
	validKey := keyB64(9)
	validHex, err := base64KeyToHex(validKey)
	if err != nil {
		t.Fatal(err)
	}
	socketPath, requests := startFakeUAPIServer(t, []string{
		"public_key=" + staleHex,
		"allowed_ip=10.13.13.2/32",
		"errno=0",
		"",
		"",
	})
	err = syncAWGUAPI(socketPath, []awgDesiredPeer{{
		PublicKey: "not-a-base64-key",
		PSK2:      keyB64(1),
		AllowedIP: "10.13.13.10/32",
	}, {
		PublicKey: validKey,
		PSK2:      keyB64(2),
		AllowedIP: "10.13.13.11/32",
	}})
	if err == nil {
		t.Fatal("bad desired key accepted")
	}
	var seenRemove bool
	var seenAdd bool
	for _, req := range collectUAPIRequests(requests) {
		if strings.Contains(req, "remove=true") && strings.Contains(req, "public_key="+staleHex) {
			seenRemove = true
		}
		if strings.Contains(req, "set=1") && strings.Contains(req, "public_key="+validHex) && !strings.Contains(req, "remove=true") {
			seenAdd = true
		}
	}
	if seenRemove {
		t.Fatalf("stale peer removed despite incomplete desired set")
	}
	if !seenAdd {
		t.Fatalf("valid desired peer was not added while reporting bad peer")
	}
}

func TestSyncAWGUAPIRemovesStalePeerWhenDesiredSetIsComplete(t *testing.T) {
	staleHex := strings.Repeat("b", 64)
	socketPath, requests := startFakeUAPIServer(t, []string{
		"public_key=" + staleHex,
		"allowed_ip=10.13.13.2/32",
		"errno=0",
		"",
		"",
	})
	if err := syncAWGUAPI(socketPath, nil); err != nil {
		t.Fatal(err)
	}
	var seenRemove bool
	for _, req := range collectUAPIRequests(requests) {
		if strings.Contains(req, "remove=true") && strings.Contains(req, "public_key="+staleHex) {
			seenRemove = true
		}
	}
	if !seenRemove {
		t.Fatalf("stale peer was not removed with complete desired set")
	}
}

func startFakeUAPIServer(t *testing.T, getResponse []string) (string, <-chan string) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "awg.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 8)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				var lines []string
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					if line == "" {
						break
					}
					lines = append(lines, line)
				}
				req := strings.Join(lines, "\n")
				requests <- req
				if strings.Contains(req, "get=1") {
					_, _ = io.WriteString(conn, strings.Join(getResponse, "\n"))
					return
				}
				_, _ = io.WriteString(conn, "errno=0\n\n")
			}(conn)
		}
	}()
	return socketPath, requests
}

func collectUAPIRequests(requests <-chan string) []string {
	var out []string
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case req := <-requests:
			out = append(out, req)
		case <-timer.C:
			return out
		}
	}
}

func TestXrayConfigSupportsOptInXHTTPReality(t *testing.T) {
	cfg := envConfig{
		StateDir:         t.TempDir(),
		RealityDest:      "awg-gw:9443",
		CamouflageDomain: "www.microsoft.com",
		XrayNetwork:      "xhttp",
		XHTTPPath:        "/operator-path",
		XHTTPMode:        "auto",
		XHTTPHost:        "cdn.operator.example",
		XHTTPExtraJSON:   `{"headers":{"X-Test":"1"}}`,
	}
	st := stateFile{
		SmokeRealityUUID: "14526b0e-6de3-4407-bf8f-d8c688160ce6",
		Reality:          realityState{PrivateKey: "priv", ShortID: "abcd", PublicKey: "pub"},
	}

	doc := xrayConfigDocument(cfg, st, nil)
	inbounds := doc["inbounds"].([]any)
	inbound := inbounds[0].(map[string]any)
	stream := inbound["streamSettings"].(map[string]any)
	if stream["network"] != "xhttp" {
		t.Fatalf("xray network=%#v want xhttp", stream["network"])
	}
	xhttp := stream["xhttpSettings"].(map[string]any)
	if xhttp["path"] != "/operator-path" || xhttp["mode"] != "auto" {
		t.Fatalf("bad xhttp settings: %#v", xhttp)
	}
	if xhttp["host"] != "cdn.operator.example" {
		t.Fatalf("bad xhttp host: %#v", xhttp)
	}
	extra := xhttp["extra"].(map[string]any)
	headers := extra["headers"].(map[string]any)
	if headers["X-Test"] != "1" {
		t.Fatalf("bad xhttp extra: %#v", xhttp)
	}

	self := selfDescribe(cfg, st)
	reality := self["reality"].(map[string]any)
	if reality["network"] != "xhttp" {
		t.Fatalf("self describe network=%#v want xhttp", reality["network"])
	}
	if reality["flow"] != "" {
		t.Fatalf("self describe xhttp flow=%#v want blank", reality["flow"])
	}
	selfXHTTP, ok := reality["xhttp"].(map[string]any)
	if !ok {
		t.Fatalf("self describe missing xhttp params: %#v", reality)
	}
	if selfXHTTP["host"] != "cdn.operator.example" {
		t.Fatalf("self describe xhttp host=%#v want configured host", selfXHTTP["host"])
	}
}

func TestXrayConfigEnablesLoopbackUserStats(t *testing.T) {
	cfg := envConfig{
		RealityDest:      "awg-gw:9443",
		CamouflageDomain: "example.com",
	}
	st := stateFile{
		SmokeRealityUUID: "14526b0e-6de3-4407-bf8f-d8c688160ce6",
		Reality:          realityState{PrivateKey: "priv", ShortID: "abcd"},
	}
	doc := xrayConfigDocument(cfg, st, []approvedDevice{{
		DeviceID:    "device-a",
		RealityUUID: "4fad2182-6de3-4407-bf8f-d8c688160ce6",
		Status:      "approved",
	}})
	inbounds := doc["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("inbounds=%d want 2", len(inbounds))
	}
	reality := inbounds[0].(map[string]any)
	clients := reality["settings"].(map[string]any)["clients"].([]any)
	deviceClient := clients[1].(map[string]any)
	if deviceClient["email"] != "device-a" || deviceClient["level"] != 0 {
		t.Fatalf("device stats identity missing: %#v", deviceClient)
	}
	apiInbound := inbounds[1].(map[string]any)
	if apiInbound["tag"] != "api" || apiInbound["listen"] != "127.0.0.1" || apiInbound["port"] != xrayAPIInPort {
		t.Fatalf("api inbound is not loopback-only: %#v", apiInbound)
	}
	api := doc["api"].(map[string]any)
	services := api["services"].([]string)
	if len(services) != 1 || services[0] != "StatsService" {
		t.Fatalf("stats service missing: %#v", api)
	}
	level := doc["policy"].(map[string]any)["levels"].(map[string]any)["0"].(map[string]any)
	if level["statsUserUplink"] != true || level["statsUserDownlink"] != true {
		t.Fatalf("per-user stats policy missing: %#v", level)
	}
	if _, ok := doc["stats"].(map[string]any); !ok {
		t.Fatalf("stats block missing: %#v", doc["stats"])
	}
}

func TestXHTTPHostDefaultsToCamouflageDomain(t *testing.T) {
	cfg := envConfig{
		CamouflageDomain: "www.microsoft.com",
		XrayNetwork:      "xhttp",
		XHTTPPath:        "/operator-path",
		XHTTPMode:        "auto",
	}
	xhttp := xhttpSettings(cfg)
	if xhttp["host"] != "www.microsoft.com" {
		t.Fatalf("xhttp host=%#v want camouflage domain fallback", xhttp["host"])
	}
}

func TestExpiredApprovedDeviceSkippedFromMaterialization(t *testing.T) {
	cfg := envConfig{StateDir: t.TempDir(), RealityDest: "awg-gw:9443", CamouflageDomain: "example.com"}
	st := stateFile{
		SmokeRealityUUID: "14526b0e-6de3-4407-bf8f-d8c688160ce6",
		Reality:          realityState{PrivateKey: "priv", ShortID: "abcd", PublicKey: "pub"},
		AWG: awgState{
			SmokePublic: keyB64(1),
			SmokePSK:    keyB64(2),
			SmokeIP:     "10.13.13.2/32",
		},
	}
	expired := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	devices := []approvedDevice{{
		DeviceID:     "expired",
		RealityUUID:  "4fad2182-6de3-4407-bf8f-d8c688160ce6",
		AWGPublicKey: keyB64(5),
		InternalIP:   "10.13.13.10/32",
		PSK2:         keyB64(6),
		Status:       "approved",
		ExpiresAt:    expired,
	}}
	if got := filterUnexpiredApprovedDevices(devices, time.Now().UTC()); len(got) != 0 {
		t.Fatalf("expired device was not filtered: %+v", got)
	}
	peers, err := writeAWGPeerRegistry(cfg, st, devices)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].PublicKey != st.AWG.SmokePublic {
		t.Fatalf("expired device leaked into desired peers: %+v", peers)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.StateDir, "awg", "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "10.13.13.10") {
		t.Fatalf("expired device leaked into registry: %s", raw)
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

func TestDistributedAPKInfoPrefersUpdateManifestOverStaleVersion(t *testing.T) {
	stateDir := t.TempDir()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	if err := os.MkdirAll(twDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := map[string]any{
		"distributed_apk": map[string]any{
			"version_code": 12,
			"version_name": "0.1.11",
			"apk_sha256":   strings.Repeat("a", 64),
			"apk_name":     "TrafficWrapper-app-v0.1.11.apk",
		},
	}
	staleRaw, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(twDir, "version.json"), staleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema":1,"ns":"apk-update-v1","seq":3,"version_code":13,"version_name":"0.1.12","apk_sha256":"` + strings.Repeat("b", 64) + `","apk_name":"TrafficWrapper-app-v0.1.12.apk"}`
	if err := os.WriteFile(filepath.Join(twDir, "update-manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	apk := distributedAPKInfo(stateDir)
	if apk["version_code"] != int64(13) || apk["version_name"] != "0.1.12" || apk["apk_sha256"] != strings.Repeat("b", 64) {
		t.Fatalf("distributed apk should come from update-manifest.json, got %#v", apk)
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
