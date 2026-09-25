package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/device"
	"github.com/TrafficWrapper/worker/core/awg/dialect"
)

func validTestConfig() Config {
	return Config{
		Interface:     defaultInterface,
		Address:       defaultAddress,
		ListenPort:    defaultPort,
		PrivateKeyHex: strings.Repeat("0", 64),
		PublicKey:     "test-public-key",
		Dialect:       dialect.Compat(),
		PeerRegistry:  defaultRegistry,
	}
}

func TestValidateConfigAcceptsDefaultAndNonDefaultInterface(t *testing.T) {
	cfg := validTestConfig()
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}

	cfg.Interface = "awg2"
	cfg.Address = "10.44.0.1/24"
	cfg.ListenPort = 52821
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("non-default config rejected: %v", err)
	}
}

func TestValidateConfigRejectsUnsafeInterfaceAndPort(t *testing.T) {
	tests := []struct {
		name      string
		iface     string
		port      int
		wantError string
	}{
		{name: "empty interface", iface: "", port: defaultPort, wantError: "interface must be set"},
		{name: "long interface", iface: "awg-interface-too-long", port: defaultPort, wantError: "15 chars"},
		{name: "slash interface", iface: "awg/2", port: defaultPort, wantError: "slash"},
		{name: "space interface", iface: "awg 2", port: defaultPort, wantError: "whitespace"},
		{name: "low port", iface: "awg2", port: 1024, wantError: "1025..65535"},
		{name: "high port", iface: "awg2", port: 65536, wantError: "1025..65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.Interface = tt.iface
			cfg.ListenPort = tt.port
			err := validateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateConfig error=%v want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestNATTableNamePreservesDefaultAndSeparatesProfiles(t *testing.T) {
	if got := natTableName(defaultInterface); got != "trafficwrapper_awg" {
		t.Fatalf("default NAT table=%q", got)
	}
	if got := natTableName("awg2"); got != "trafficwrapper_awg_awg2" {
		t.Fatalf("custom NAT table=%q", got)
	}
}

func TestDeviceConfigLinesDisableServerSideKeepalive(t *testing.T) {
	cfg := validTestConfig()
	lines := deviceConfigLines(cfg, []restoredPeer{
		{
			PublicKeyHex: strings.Repeat("1", 64),
			PSKHex:       strings.Repeat("2", 64),
			AllowedIP:    "10.13.13.10/32",
		},
		{
			PublicKeyHex: strings.Repeat("3", 64),
			PSKHex:       strings.Repeat("4", 64),
			AllowedIP:    "10.13.13.11/32",
		},
	})
	if err := validatePeerUAPIBlocks(lines, 2, "persistent_keepalive_interval=0"); err != nil {
		t.Fatalf("server peer config malformed: %v\n%s", err, strings.Join(lines, "\n"))
	}
}

func TestDeviceConfigLinesUseConfiguredServerKeepalive(t *testing.T) {
	cfg := validTestConfig()
	cfg.ServerKeepalive = 17
	lines := deviceConfigLines(cfg, []restoredPeer{{
		PublicKeyHex: strings.Repeat("1", 64),
		PSKHex:       strings.Repeat("2", 64),
		AllowedIP:    "10.13.13.10/32",
	}})
	if err := validatePeerUAPIBlocks(lines, 1, "persistent_keepalive_interval=17"); err != nil {
		t.Fatalf("configured server peer keepalive missing: %v\n%s", err, strings.Join(lines, "\n"))
	}
}

func TestServerKeepaliveEnvOverridesConfigAndRejectsInvalidValues(t *testing.T) {
	t.Setenv("AWG_SERVER_KEEPALIVE", "")
	got, err := serverKeepaliveFromEnv(9)
	if err != nil || got != 9 {
		t.Fatalf("config fallback=%d err=%v, want 9", got, err)
	}
	t.Setenv("AWG_SERVER_KEEPALIVE", "17")
	got, err = serverKeepaliveFromEnv(9)
	if err != nil || got != 17 {
		t.Fatalf("env override=%d err=%v, want 17", got, err)
	}
	for _, value := range []string{"invalid", "-1", "65536"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("AWG_SERVER_KEEPALIVE", value)
			if _, err := serverKeepaliveFromEnv(0); err == nil {
				t.Fatalf("invalid keepalive %q accepted", value)
			}
		})
	}
}

func TestPeerUAPIBlockValidationRejectsKeepaliveMutants(t *testing.T) {
	valid := []string{
		"private_key=" + strings.Repeat("0", 64),
		"listen_port=51821",
		"public_key=" + strings.Repeat("1", 64),
		"preshared_key=" + strings.Repeat("2", 64),
		"persistent_keepalive_interval=0",
		"replace_allowed_ips=true",
		"allowed_ip=10.13.13.10/32",
		"public_key=" + strings.Repeat("3", 64),
		"preshared_key=" + strings.Repeat("4", 64),
		"persistent_keepalive_interval=0",
		"replace_allowed_ips=true",
		"allowed_ip=10.13.13.11/32",
	}
	if err := validatePeerUAPIBlocks(valid, 2, "persistent_keepalive_interval=0"); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	interfaceKeepalive := append([]string(nil), valid...)
	interfaceKeepalive = append(interfaceKeepalive[:2], append([]string{"persistent_keepalive_interval=0"}, interfaceKeepalive[2:]...)...)
	if err := validatePeerUAPIBlocks(interfaceKeepalive, 2, "persistent_keepalive_interval=0"); err == nil {
		t.Fatal("keepalive in interface section was not rejected")
	}
	missingFirst := append([]string(nil), valid...)
	missingFirst = append(missingFirst[:4], missingFirst[5:]...)
	if err := validatePeerUAPIBlocks(missingFirst, 2, "persistent_keepalive_interval=0"); err == nil {
		t.Fatal("missing keepalive in first peer block was not rejected")
	}
}

func validatePeerUAPIBlocks(lines []string, wantPeers int, keepaliveLine string) error {
	peers := 0
	keepalivePositions := map[int]struct{}{}
	for i, line := range lines {
		if !strings.HasPrefix(line, "public_key=") {
			continue
		}
		peers++
		if i+4 >= len(lines) ||
			!strings.HasPrefix(lines[i+1], "preshared_key=") ||
			lines[i+2] != keepaliveLine ||
			lines[i+3] != "replace_allowed_ips=true" ||
			!strings.HasPrefix(lines[i+4], "allowed_ip=") {
			end := i + 5
			if end > len(lines) {
				end = len(lines)
			}
			return fmt.Errorf("peer block malformed at %d: %q", i, lines[i:end])
		}
		keepalivePositions[i+2] = struct{}{}
	}
	if peers != wantPeers {
		return fmt.Errorf("peers=%d want %d", peers, wantPeers)
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, "persistent_keepalive_interval=") {
			continue
		}
		if _, ok := keepalivePositions[i]; !ok {
			return fmt.Errorf("keepalive outside peer block at %d", i)
		}
	}
	return nil
}

func TestClientIsolationBlocksPrivateDestinationsFromTunnel(t *testing.T) {
	joined := []string{}
	for _, args := range clientIsolationCommands("awg1", true, true) {
		joined = append(joined, strings.Join(args, " "))
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{"iifname awg1 ip daddr", "169.254.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "fc00::/7", "hook forward", "drop", "tcp dport { 25, 465, 587 } drop"} {
		if !strings.Contains(all, want) {
			t.Fatalf("isolation rules missing %q:\n%s", want, all)
		}
	}
	onlySMTP := ""
	for _, args := range clientIsolationCommands("awg1", false, true) {
		onlySMTP += strings.Join(args, " ") + "\n"
	}
	if strings.Contains(onlySMTP, "169.254.0.0/16") || !strings.Contains(onlySMTP, "dport") {
		t.Fatalf("private opt-out must keep only the SMTP rule:\n%s", onlySMTP)
	}
}

func TestIsolationFromEnvUsesStrictBool(t *testing.T) {
	cases := []struct {
		allowPrivate, blockSMTP string
		want                    isolationSettings
	}{
		{"", "", isolationSettings{BlockPrivate: true, BlockSMTP: true}},
		{"1", "0", isolationSettings{BlockPrivate: false, BlockSMTP: false}},
		{"true", "false", isolationSettings{BlockPrivate: false, BlockSMTP: false}},
		{"No", "YES", isolationSettings{BlockPrivate: true, BlockSMTP: true}},
		{"off", "on", isolationSettings{BlockPrivate: true, BlockSMTP: true}},
	}
	for _, tc := range cases {
		t.Setenv("WORKER_ALLOW_PRIVATE_EGRESS", tc.allowPrivate)
		t.Setenv("WORKER_BLOCK_SMTP", tc.blockSMTP)
		got, err := isolationFromEnv()
		if err != nil || got != tc.want {
			t.Fatalf("allow_private=%q smtp=%q: %+v, %v want %+v", tc.allowPrivate, tc.blockSMTP, got, err, tc.want)
		}
	}
	for _, env := range []string{"WORKER_ALLOW_PRIVATE_EGRESS", "WORKER_BLOCK_SMTP"} {
		t.Setenv("WORKER_ALLOW_PRIVATE_EGRESS", "")
		t.Setenv("WORKER_BLOCK_SMTP", "")
		t.Setenv(env, "2")
		if _, err := isolationFromEnv(); err == nil {
			t.Fatalf("%s=2 accepted", env)
		}
	}
}

func TestLoadActivePeersSkipsMalformedEntries(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	registry := `{"clients":[
		{"wg_public_key":"bad","internal_ip":"10.13.13.9/32","psk2":"` + good + `"},
		{"wg_public_key":"` + good + `","internal_ip":"10.13.13.10","psk2":"` + good + `"},
		{"wg_public_key":"` + good + `","internal_ip":"10.13.13.0/24","psk2":"` + good + `"},
		{"wg_public_key":"` + good + `","internal_ip":"10.13.13.11/32","psk2":"` + good + `"}
	]}`
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := os.WriteFile(path, []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}
	peers, err := loadActivePeers(path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].AllowedIP != "10.13.13.11/32" {
		t.Fatalf("malformed entries must be skipped, valid kept: %+v", peers)
	}
}

func TestAWGLogLevelDefaultsToErrors(t *testing.T) {
	cases := map[string]int{"": device.LogLevelError, "verbose": device.LogLevelVerbose, "SILENT": device.LogLevelSilent}
	for value, want := range cases {
		got, err := awgLogLevel(value)
		if err != nil || got != want {
			t.Fatalf("awgLogLevel(%q)=%d,%v want %d", value, got, err, want)
		}
	}
	if _, err := awgLogLevel("loud"); err == nil {
		t.Fatal("unknown level accepted")
	}
}

func TestRateLimitsFromRegistryBuildTCRules(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	registry := `{"clients":[
		{"wg_public_key":"` + key + `","internal_ip":"10.13.13.10/32","psk2":"` + key + `","download_mbps":20,"upload_mbps":5},
		{"wg_public_key":"` + key + `","internal_ip":"10.13.13.11/32","psk2":"` + key + `"},
		{"wg_public_key":"` + key + `","internal_ip":"10.13.13.12/32","psk2":"` + key + `","download_mbps":50,"expires_at":"2000-01-01T00:00:00Z"}
	]}`
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := os.WriteFile(path, []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}
	limits, err := loadRateLimits(path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(limits) != 1 || limits[0].IP != "10.13.13.10" || limits[0].DownloadMbps != 20 || limits[0].UploadMbps != 5 {
		t.Fatalf("limits=%+v", limits)
	}
	var all []string
	for _, args := range rateLimitCommands("awg1", limits) {
		all = append(all, strings.Join(args, " "))
	}
	joined := strings.Join(all, "\n")
	for _, want := range []string{
		"tc qdisc add dev awg1 root handle 1: htb",
		"tc class add dev awg1 parent 1: classid 1:10 htb rate 20mbit ceil 20mbit",
		"match ip dst 10.13.13.10/32 flowid 1:10",
		"match ip src 10.13.13.10/32 police rate 5mbit burst 32768b drop",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	if cleared := rateLimitCommands("awg1", nil); len(cleared) != 2 {
		t.Fatalf("no limits must only clear shaping: %v", cleared)
	}
}
