package bundle

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"aead.dev/minisign"
)

func TestApplyDiscoveredEndpointsVerifiesMinisign(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	message := mustBundleJSON(t)
	signature := string(minisign.SignWithComments(priv, []byte(message), "test", "trusted"))
	req := requestJSON(t, string(rawPub), message, signature)

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if !result.OK || result.Selected != "awg" {
		t.Fatalf("signed bundle rejected: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsWrongMinisign(t *testing.T) {
	pub, _, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	message := mustBundleJSON(t)
	signature := string(minisign.SignWithComments(otherPriv, []byte(message), "test", "untrusted"))
	req := requestJSON(t, string(rawPub), message, signature)

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "invalid signature") {
		t.Fatalf("wrong signature accepted or wrong error: %+v", result)
	}
}

func mustBundleJSON(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schema":     2,
		"ns":         "rendezvous-v1",
		"seq":        7,
		"issued_at":  "2026-06-13T10:00:00Z",
		"expires_at": "2026-06-13T22:00:00Z",
		"endpoints": map[string]any{
			"awg":     []any{map[string]any{"priority": 0}},
			"reality": []any{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func requestJSON(t *testing.T, publicKey string, endpointsJSON string, signature string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"endpoints_json":         endpointsJSON,
		"endpoints_json_minisig": signature,
		"public_key":             publicKey,
		"now":                    "2026-06-13T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func decodeApplyResult(t *testing.T, raw string) applyDiscoveredResult {
	t.Helper()
	var result applyDiscoveredResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("decode apply result %s: %v", raw, err)
	}
	return result
}
