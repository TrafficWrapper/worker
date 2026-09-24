package serverpeer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestKeyB64ToHex(t *testing.T) {
	key := make([]byte, 32)
	key[0], key[31] = 0xab, 0x01
	got, err := KeyB64ToHex(" " + base64.StdEncoding.EncodeToString(key) + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := "ab" + strings.Repeat("00", 30) + "01"; got != want {
		t.Fatalf("KeyB64ToHex()=%q want %q", got, want)
	}
	if _, err := KeyB64ToHex(base64.StdEncoding.EncodeToString(key[:31])); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := KeyB64ToHex("not base64!"); err == nil {
		t.Fatal("invalid base64 accepted")
	}
}

func TestRegistryJSONShape(t *testing.T) {
	raw, err := json.Marshal(Registry{Clients: []RegistryClient{{
		WGPublicKey: "pub",
		InternalIP:  "10.13.13.10/32",
		PSK2:        "psk",
		ExpiresAt:   time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"clients":[{"wg_public_key":"pub","internal_ip":"10.13.13.10/32","psk2":"psk","expires_at":"2030-01-02T03:04:05Z"}]}`
	if string(raw) != want {
		t.Fatalf("registry JSON=%s want %s", raw, want)
	}
}
