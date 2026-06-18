package transport

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"

	awgdialect "github.com/TrafficWrapper/worker/core/awg/dialect"
)

func TestApplyDiscoveredEndpointsMergesAWGWithStoredSecrets(t *testing.T) {
	signer := newTestSigner(t)
	base := testBaseConfig(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	req := signer.request(t, bundle, base, 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if !result.OK {
		t.Fatalf("ApplyDiscoveredEndpoints failed: %s", result.Error)
	}
	if result.Seq != 10 {
		t.Fatalf("seq=%d, want 10", result.Seq)
	}
	if result.EgressIP != "203.0.113.77" {
		t.Fatalf("egress_ip=%q", result.EgressIP)
	}
	if _, err := parseConfig(result.ConfigJSON); err != nil {
		t.Fatalf("merged config does not parse: %v\n%s", err, result.ConfigJSON)
	}
	var merged config
	if err := json.Unmarshal([]byte(result.ConfigJSON), &merged); err != nil {
		t.Fatal(err)
	}
	var original config
	if err := json.Unmarshal([]byte(base), &original); err != nil {
		t.Fatal(err)
	}
	if merged.PrivateKey != original.PrivateKey {
		t.Fatal("private_key was not preserved")
	}
	if merged.PSK2 != original.PSK2 {
		t.Fatal("psk2 was not preserved")
	}
	if merged.InternalIP != original.InternalIP {
		t.Fatal("internal_ip was not preserved")
	}
	if merged.Endpoint != "198.51.100.50:51821" {
		t.Fatalf("endpoint=%q", merged.Endpoint)
	}
	if merged.ServerPublicKey != testDiscoveredServerKey {
		t.Fatalf("server_public_key=%q", merged.ServerPublicKey)
	}
	if !awgdialect.IsCompat(merged.AWGPreset) {
		t.Fatalf("awg_preset was not applied: %+v", merged.AWGPreset)
	}
	if merged.MTU != original.MTU {
		t.Fatalf("mtu=%d, want original %d", merged.MTU, original.MTU)
	}
}

func TestApplyDiscoveredEndpointsRejectsTamperedSignedBundle(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	message := mustJSON(t, bundle)
	signature := signer.sign(message)
	tampered := strings.Replace(message, "198.51.100.50", "198.51.100.51", 1)
	req := requestJSON(t, signer.publicKey, tampered, signature, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "invalid signature") {
		t.Fatalf("tampered bundle accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsWrongSignature(t *testing.T) {
	signer := newTestSigner(t)
	other := newTestSigner(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	message := mustJSON(t, bundle)
	req := requestJSON(t, signer.publicKey, message, other.sign(message), testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "invalid signature") {
		t.Fatalf("wrong signature accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRequiresPublicKey(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	message := mustJSON(t, bundle)
	req := requestJSON(t, "", message, signer.sign(message), testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "public_key is required") {
		t.Fatalf("missing public key accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsExpiredBundle(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T11:00:00Z")
	req := signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "expired") {
		t.Fatalf("expired bundle accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsRollback(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testBundle(t, 9, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	req := signer.request(t, bundle, testBaseConfig(t), 10, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "rollback") {
		t.Fatalf("rollback bundle accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsWrongNamespace(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	bundle["ns"] = "version-v1"
	req := signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "namespace") {
		t.Fatalf("wrong namespace accepted or wrong error: %+v", result)
	}
}

func TestApplyDiscoveredEndpointsRejectsPublicBundleSecrets(t *testing.T) {
	signer := newTestSigner(t)
	bundle := testBundle(t, 10, "2026-06-13T10:00:00Z", "2026-06-13T22:00:00Z")
	awg := bundle["endpoints"].(map[string]any)["awg"].([]any)[0].(map[string]any)
	awg["psk2"] = testKey(8)
	req := signer.request(t, bundle, testBaseConfig(t), 9, "2026-06-13T12:00:00Z")

	result := decodeApplyResult(t, ApplyDiscoveredEndpoints(req))
	if result.OK || !strings.Contains(result.Error, "forbidden discovery field") {
		t.Fatalf("secret-bearing bundle accepted or wrong error: %+v", result)
	}
}

type testSigner struct {
	publicKey  string
	privateKey minisign.PrivateKey
}

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{publicKey: string(rawPub), privateKey: priv}
}

func (s testSigner) sign(message string) string {
	return string(minisign.SignWithComments(
		s.privateKey,
		[]byte(message),
		"test rendezvous fixture",
		"signature from test key",
	))
}

func (s testSigner) request(t *testing.T, bundle map[string]any, baseConfig string, maxSeen int64, now string) string {
	t.Helper()
	message := mustJSON(t, bundle)
	return requestJSON(t, s.publicKey, message, s.sign(message), baseConfig, maxSeen, now)
}

func requestJSON(t *testing.T, publicKey, endpointsJSON, signature, baseConfig string, maxSeen int64, now string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"endpoints_json":         endpointsJSON,
		"endpoints_json_minisig": signature,
		"public_key":             publicKey,
		"base_config_json":       baseConfig,
		"max_seen_seq":           maxSeen,
		"now":                    now,
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

func testBundle(t *testing.T, seq int64, issuedAt string, expiresAt string) map[string]any {
	t.Helper()
	return map[string]any{
		"schema":     2,
		"ns":         "rendezvous-v1",
		"seq":        seq,
		"issued_at":  issuedAt,
		"expires_at": expiresAt,
		"endpoints": map[string]any{
			"awg": []any{
				map[string]any{
					"priority":          0,
					"endpoint":          "198.51.100.50:51821",
					"server_public_key": testDiscoveredServerKey,
					"awg_preset":        awgdialect.Compat(),
				},
			},
			"reality": []any{
				map[string]any{
					"priority":    0,
					"transport":   "xray-vless-reality-vision",
					"address":     "tw.example.test",
					"egress_ip":   "203.0.113.77",
					"port":        443,
					"uuid":        "f60fc87e-691f-490c-999c-8313881742cc",
					"flow":        "xtls-rprx-vision",
					"security":    "reality",
					"network":     "tcp",
					"serverName":  "tw.example.test",
					"publicKey":   "4nkiNFwR_CaD1I4TSDpwnOECstRmPXj21CtitT3AgzA",
					"shortId":     "d713c2142c5b9035",
					"fingerprint": "chrome",
					"spiderX":     "/",
				},
			},
		},
	}
}

func testBaseConfig(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(config{
		PrivateKey:      testKey(1),
		InternalIP:      "10.13.13.42/32",
		Endpoint:        "203.0.113.10:51821",
		ServerPublicKey: testKey(2),
		PSK2:            testKey(3),
		AWGPreset:       awgdialect.Compat(),
		SOCKSListen:     "127.0.0.1:18080",
		MTU:             1420,
		DNSServers:      []string{"1.1.1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func testKey(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

var testDiscoveredServerKey = testKey(4)

func TestDiscoveryNowUsesUTC(t *testing.T) {
	got, err := discoveryNow("2026-06-13T12:00:00+03:00")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 6, 13, 9, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}
