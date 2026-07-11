package main

import (
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
	lines := deviceConfigLines(cfg, []restoredPeer{{
		PublicKeyHex: strings.Repeat("1", 64),
		PSKHex:       strings.Repeat("2", 64),
		AllowedIP:    "10.13.13.10/32",
	}})
	raw := strings.Join(lines, "\n")
	if !strings.Contains(raw, "persistent_keepalive_interval=0") {
		t.Fatalf("server peer does not explicitly disable keepalive: %s", raw)
	}
	if !strings.Contains(raw, "allowed_ip=10.13.13.10/32") {
		t.Fatalf("server peer config incomplete: %s", raw)
	}
}
