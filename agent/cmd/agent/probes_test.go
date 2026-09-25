package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func startProbeTarget(t *testing.T, h2 bool) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	old := probeRootCAs
	probeRootCAs = pool
	t.Cleanup(func() { probeRootCAs = old })
	return strings.TrimPrefix(srv.URL, "https://")
}

func TestTLSProbeAcceptsTLS13H2Target(t *testing.T) {
	addr := startProbeTarget(t, true)
	report := probeCamouflageDest(context.Background(), addr, "example.com")
	if !report.OK || !report.TLS13 || !report.H2 || !report.X25519 || !report.CertMatches {
		t.Fatalf("good target rejected: %+v", report)
	}
}

func TestTLSProbeFlagsMissingH2AndWrongName(t *testing.T) {
	addr := startProbeTarget(t, false)
	report := tlsProbe(context.Background(), addr, "example.com")
	if report.OK || report.H2 {
		t.Fatalf("target without h2 accepted: %+v", report)
	}
	report = tlsProbe(context.Background(), addr, "www.example.net")
	if report.OK || report.CertMatches || !strings.Contains(report.Error, "certificate") || !report.TLS13 {
		t.Fatalf("certificate for another name accepted: %+v", report)
	}
}

func TestCDNIssuerDetection(t *testing.T) {
	cert := &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Cloudflare, Inc."}}}
	if cdnIssuer(cert) != "cloudflare" {
		t.Fatal("cloudflare issuer not detected")
	}
	if cdnIssuer(&x509.Certificate{Issuer: pkix.Name{Organization: []string{"Let's Encrypt"}}}) != "" {
		t.Fatal("regular CA flagged as CDN")
	}
}

func TestSelfCheckStatusReflectsProbes(t *testing.T) {
	old := currentHealth.Load()
	t.Cleanup(func() { currentHealth.Store(old) })
	currentHealth.Store(&healthState{Camouflage: &probeReport{OK: true}, Reality: &probeReport{OK: false}})
	if got := selfCheckStatus(); got != "degraded: reality" {
		t.Fatalf("status=%q", got)
	}
	currentHealth.Store(&healthState{Camouflage: &probeReport{OK: true}, Reality: &probeReport{OK: true}})
	if got := selfCheckStatus(); got != "ok" {
		t.Fatalf("status=%q", got)
	}
}

func TestXrayRoutingBlocksAbuseByDefaultFlags(t *testing.T) {
	cfg := envConfig{BlockSMTP: true, BlockBitTorrent: true, RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net"}
	doc := xrayConfigDocument(cfg, hardeningTestState(), nil)
	inbound := doc["inbounds"].([]any)[0].(map[string]any)
	if _, ok := inbound["sniffing"]; !ok {
		t.Fatal("sniffing must be enabled for protocol rules")
	}
	raw, _ := json.Marshal(xrayRouting(cfg))
	if !strings.Contains(string(raw), `"bittorrent"`) || !strings.Contains(string(raw), `"25,465,587"`) {
		t.Fatalf("abuse rules missing: %s", raw)
	}
}

func TestFailedProbesAreRetriedWithBackoff(t *testing.T) {
	if nextProbeDelay(0) != probeInterval {
		t.Fatal("success does not wait the regular interval")
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute}
	for i, w := range want {
		if got := nextProbeDelay(i + 1); got != w {
			t.Fatalf("failure %d: retry after %v, want %v", i+1, got, w)
		}
	}
	if nextProbeDelay(50) != probeInterval {
		t.Fatal("backoff exceeds the regular interval")
	}
}
