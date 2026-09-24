package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicAWGConfigJSONPinsHostnameEndpointWithExpectedEgressIP(t *testing.T) {
	var route publicRouteSpec
	if err := json.Unmarshal([]byte(fmt.Sprintf(
		`{"endpoint":"worker.example:51888","egress_ip":"198.51.100.44","public_key":%q}`,
		testKey(2),
	)), &route); err != nil {
		t.Fatal(err)
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	raw, err := publicAWGConfigJSON(&route, req, "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "198.51.100.44:51888" {
		t.Fatalf("endpoint=%q want pinned IP endpoint", cfg.Endpoint)
	}
}

func TestPublicAWGConfigJSONRejectsHostnameEndpointWithoutPinnedIP(t *testing.T) {
	route := &publicRouteSpec{
		Endpoint:  "worker.example:51888",
		PublicKey: testKey(2),
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	if _, err := publicAWGConfigJSON(route, req, "127.0.0.1:18080"); err == nil {
		t.Fatal("hostname endpoint without egress_ip was accepted")
	}
}

func TestPublicHTTPClientSharesTransportAndUsesContextTimeout(t *testing.T) {
	a, b := publicHTTPClient(), publicHTTPClient()
	if a.Transport != publicHTTPTransport || b.Transport != publicHTTPTransport {
		t.Fatal("public http client does not reuse the shared transport")
	}
	if a.Timeout != 0 {
		t.Fatalf("client timeout=%s overrides request context", a.Timeout)
	}
	if publicHTTPTransport.IdleConnTimeout <= 0 {
		t.Fatal("shared transport keeps idle connections forever")
	}
}

func TestPostJSONHonoursContextDeadline(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	var resp map[string]any
	err := postJSON(ctx, publicHTTPClient(), server.URL, map[string]string{}, &resp)
	if err == nil {
		t.Fatal("request succeeded past context deadline")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("request did not stop at context deadline")
	}
}

func TestPostJSONSanitizesUnauthenticatedErrorBody(t *testing.T) {
	body := "bad\x1b[31m\nrequest" + strings.Repeat("A", 5000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, body, http.StatusBadRequest)
	}))
	defer server.Close()

	var resp map[string]any
	err := postJSON(context.Background(), publicHTTPClient(), server.URL, map[string]string{}, &resp)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unauthenticated server response") {
		t.Fatalf("error not marked unauthenticated: %q", msg)
	}
	if strings.ContainsAny(msg, "\x1b\n\r") {
		t.Fatalf("error contains control characters: %q", msg)
	}
	if len(msg) > 300 {
		t.Fatalf("error length=%d, want truncated", len(msg))
	}
}

func TestSanitizeUntrustedText(t *testing.T) {
	got := sanitizeUntrustedText("  a\u202eb\x00c\n ")
	if got != "a b c" {
		t.Fatalf("got %q", got)
	}
	long := sanitizeUntrustedText(strings.Repeat("я", 500))
	if n := len([]rune(long)); n != maxUntrustedErrorRunes+3 {
		t.Fatalf("rune length=%d", n)
	}
}

func TestApplyPublicPlatformConfigKeepsStoredConfigs(t *testing.T) {
	setPendingProvision(t, "stored-default", "stored-awg-ru")
	base := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
	}
	route := &publicRouteSpec{Endpoint: "203.0.113.10:51821"}

	onlyRU := base
	onlyRU.AWGRU = route
	result, err := applyPublicPlatformConfig(onlyRU)
	if err != nil {
		t.Fatal(err)
	}
	if result.ConfigStored || !result.AWGRUConfigStored {
		t.Fatalf("result=%+v", result)
	}
	pendingProvision.Lock()
	defaultJSON, ruJSON := pendingProvision.configJSON, pendingProvision.awgRUConfigJSON
	pendingProvision.Unlock()
	if defaultJSON != "stored-default" {
		t.Fatalf("default config was overwritten: %q", defaultJSON)
	}
	if ruJSON == "stored-awg-ru" || ruJSON == "" {
		t.Fatal("awg_ru config was not updated")
	}

	onlyDefault := base
	onlyDefault.AWG = route
	if _, err := applyPublicPlatformConfig(onlyDefault); err != nil {
		t.Fatal(err)
	}
	pendingProvision.Lock()
	defaultJSON, ruAfter := pendingProvision.configJSON, pendingProvision.awgRUConfigJSON
	pendingProvision.Unlock()
	if defaultJSON == "stored-default" {
		t.Fatal("default config was not updated")
	}
	if ruAfter != ruJSON {
		t.Fatal("awg_ru config was cleared by request without awg_ru")
	}
}

func TestApplyPublicPlatformConfigPinsSignerKey(t *testing.T) {
	resetDiscoveryTrust(t)
	setPendingProvision(t, "", "")
	signer := newTestSigner(t)
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		SignerPublicKey: signer.publicKey,
	}
	if _, err := applyPublicPlatformConfig(req); err != nil {
		t.Fatal(err)
	}
	if _, _, err := discoveryTrustSnapshot(signer.publicKey); err != nil {
		t.Fatalf("signer key not pinned: %v", err)
	}
	req.SignerPublicKey = newTestSigner(t).publicKey
	if _, err := applyPublicPlatformConfig(req); err == nil {
		t.Fatal("different signer key replaced pinned key")
	}
}
