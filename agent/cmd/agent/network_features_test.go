package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicAddressV6Validation(t *testing.T) {
	if got, err := publicAddressV6("[2a01:4f8:c0c:1234::2]"); err != nil || got != "2a01:4f8:c0c:1234::2" {
		t.Fatalf("bracketed v6 rejected: %q %v", got, err)
	}
	if got, err := publicAddressV6("2a01:4f8:c0c:1234::1"); err != nil || got != "2a01:4f8:c0c:1234::1" {
		t.Fatalf("global v6 rejected: %q %v", got, err)
	}
	for _, bad := range []string{"203.0.113.5", "fe80::1", "::ffff:198.51.100.1", "nonsense"} {
		if _, err := publicAddressV6(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if got, _ := publicAddressV6(""); got != "" {
		t.Fatal("empty value must stay empty")
	}
}

func TestSelfDescribeAdvertisesV6AndDNS(t *testing.T) {
	cfg := envConfig{
		PublicAddress:    "198.51.100.7",
		PublicAddressV6:  "2a01:4f8:c0c:1234::1",
		DNSEnabled:       true,
		XrayPort:         2053,
		CamouflageDomain: "www.example.net",
		RealityDest:      "www.example.net:443",
		AWGProfiles: []awgInboundProfile{
			{Name: "awg", Interface: "awg1", ListenPort: 51821, PublicPort: 51888, Subnet: "10.13.13.0/24", Gateway: "10.13.13.1"},
			{Name: "next", Interface: "awg2", ListenPort: 51822, PublicPort: 51889, Subnet: "10.44.0.0/24", Gateway: "10.44.0.1"},
		},
	}
	desc := selfDescribe(cfg, hardeningTestState())
	awg := desc["awg"].(map[string]any)
	if awg["endpoint_v6"] != "[2a01:4f8:c0c:1234::1]:51888" {
		t.Fatalf("endpoint_v6=%v", awg["endpoint_v6"])
	}
	if dns := awg["dns"].([]string); len(dns) != 1 || dns[0] != "10.13.13.1" {
		t.Fatalf("dns=%v", dns)
	}
	next := desc["awg_profiles"].([]any)[1].(map[string]any)
	if len(next["dns"].([]string)) != 0 {
		t.Fatal("resolver advertised on a profile without it")
	}
	profile := desc["reality_profiles"].([]any)[0].(map[string]any)
	if profile["address_v6"] != "2a01:4f8:c0c:1234::1" {
		t.Fatalf("reality address_v6=%v", profile["address_v6"])
	}
}

func TestAWGRegistryCarriesRateLimits(t *testing.T) {
	device := approvedDevice{DeviceID: "a", RealityUUID: "4fad2182-6de3-4407-bf8f-d8c688160ce6", AWGPublicKey: keyB64(5), InternalIP: "10.13.13.10/32", PSK2: keyB64(6), Status: "approved"}
	device.Limits.DownloadMbps = 25
	device.Limits.UploadMbps = 5
	registry, _ := buildAWGPeerRegistryForProfile(stateFile{}, []approvedDevice{device}, awgInboundProfile{Name: "awg", Subnet: "10.13.13.0/24"}, false)
	if len(registry.Clients) != 1 || registry.Clients[0].DownloadMbps != 25 || registry.Clients[0].UploadMbps != 5 {
		t.Fatalf("limits not carried: %+v", registry.Clients)
	}
	device.Limits.UploadMbps = -1
	if _, err := normalizeApprovedDevice(device); err == nil || !strings.Contains(err.Error(), "limits") {
		t.Fatalf("negative limit accepted: %v", err)
	}
}

func TestPublicAddressV6AutoWarnsWhenNothingFound(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no ipv6", http.StatusBadGateway)
	}))
	defer srv.Close()
	oldURL := ipv6EchoURL
	ipv6EchoURL = srv.URL
	t.Cleanup(func() { ipv6EchoURL = oldURL })
	addr, err := publicAddressV6("auto")
	if err != nil || addr != "" {
		t.Fatalf("addr=%q err=%v", addr, err)
	}
	if !strings.Contains(logs.String(), "PUBLIC_ADDRESS_V6=auto") {
		t.Fatalf("no warning logged: %s", logs.String())
	}
}
