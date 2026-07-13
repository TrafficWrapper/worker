package main

import (
	"fmt"
	"strings"
	"testing"

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
