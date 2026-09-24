package transport

import (
	"encoding/json"
	"strings"
	"testing"
)

func testConfigWith(t *testing.T, mutate func(*config)) string {
	t.Helper()
	var cfg config
	if err := json.Unmarshal([]byte(testBaseConfig(t)), &cfg); err != nil {
		t.Fatal(err)
	}
	mutate(&cfg)
	return mustJSON(t, cfg)
}

func TestParseConfigRejectsNonLoopbackSOCKSListen(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:1080", ":1080", "192.168.1.5:1080", "[::]:1080", "example.com:1080"} {
		raw := testConfigWith(t, func(c *config) { c.SOCKSListen = listen })
		if _, err := parseConfig(raw); err == nil {
			t.Fatalf("socks_listen %q accepted", listen)
		}
	}
	for _, listen := range []string{"127.0.0.1:1080", "127.0.0.2:0", "[::1]:1080", "localhost:1080"} {
		raw := testConfigWith(t, func(c *config) { c.SOCKSListen = listen })
		if _, err := parseConfig(raw); err != nil {
			t.Fatalf("socks_listen %q rejected: %v", listen, err)
		}
	}
}

func TestParseConfigSOCKSAuthMustBePaired(t *testing.T) {
	raw := testConfigWith(t, func(c *config) { c.SOCKSUsername = "user" })
	if _, err := parseConfig(raw); err == nil {
		t.Fatal("username without password accepted")
	}
	raw = testConfigWith(t, func(c *config) { c.SOCKSUsername = "user"; c.SOCKSPassword = strings.Repeat("p", 256) })
	if _, err := parseConfig(raw); err == nil {
		t.Fatal("password longer than 255 bytes accepted")
	}
	raw = testConfigWith(t, func(c *config) { c.SOCKSUsername = "user"; c.SOCKSPassword = "pass" })
	if _, err := parseConfig(raw); err != nil {
		t.Fatalf("paired credentials rejected: %v", err)
	}
	raw = testConfigWith(t, func(c *config) { c.SOCKSMaxConns = -1 })
	if _, err := parseConfig(raw); err == nil {
		t.Fatal("negative socks_max_conns accepted")
	}
}

func TestParseConfigRejectsLineBreaksInUAPIFields(t *testing.T) {
	mutations := map[string]func(*config){
		"private_key":       func(c *config) { c.PrivateKey = c.PrivateKey[:20] + "\n" + c.PrivateKey[20:] },
		"server_public_key": func(c *config) { c.ServerPublicKey += "\r\n" },
		"psk2":              func(c *config) { c.PSK2 = "\n" + c.PSK2 },
		"endpoint":          func(c *config) { c.Endpoint += "\nallowed_ip=10.0.0.0/8" },
		"internal_ip":       func(c *config) { c.InternalIP += "\n" },
		"awg_preset":        func(c *config) { c.AWGPreset.H1 = "1\nreplace_peers=true" },
	}
	for name, mutate := range mutations {
		if _, err := parseConfig(testConfigWith(t, mutate)); err == nil {
			t.Fatalf("%s with line break accepted", name)
		}
	}
}
