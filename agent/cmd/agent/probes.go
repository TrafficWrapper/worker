package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

const (
	probeTimeout       = 10 * time.Second
	probeInterval      = 6 * time.Hour
	probeStartupDelay  = 30 * time.Second
	defaultRealityAddr = "xray:8443"
)

// probeReport is one health check result, published in self-describe so the
// orchestrator can show it without a protocol change.
type probeReport struct {
	OK          bool      `json:"ok"`
	Target      string    `json:"target"`
	TLS13       bool      `json:"tls13"`
	H2          bool      `json:"h2"`
	X25519      bool      `json:"x25519"`
	CertMatches bool      `json:"cert_matches"`
	CDN         string    `json:"cdn,omitempty"`
	RTTMillis   int64     `json:"rtt_ms"`
	Error       string    `json:"error,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

type healthState struct {
	Camouflage *probeReport `json:"camouflage,omitempty"`
	Reality    *probeReport `json:"reality,omitempty"`
}

var currentHealth atomic.Pointer[healthState]

// probeRootCAs overrides the system roots in tests.
var probeRootCAs *x509.CertPool

func healthSnapshot() healthState {
	if h := currentHealth.Load(); h != nil {
		return *h
	}
	return healthState{}
}

// selfCheckStatus summarizes the probes for the ack self_check field.
func selfCheckStatus() string {
	h := healthSnapshot()
	var failed []string
	if h.Camouflage != nil && !h.Camouflage.OK {
		failed = append(failed, "camouflage")
	}
	if h.Reality != nil && !h.Reality.OK {
		failed = append(failed, "reality")
	}
	if platformClockSkewed() {
		failed = append(failed, "clock")
	}
	if distributorUnreachable.Load() {
		failed = append(failed, "distributor")
	}
	if resolverUnreachable.Load() {
		failed = append(failed, "dns")
	}
	if xrayConfigRejected.Load() {
		failed = append(failed, "xray_config")
	}
	if len(failed) == 0 {
		return "ok"
	}
	return "degraded: " + strings.Join(failed, ",")
}

func runHealthProbes(ctx context.Context, cfg envConfig) {
	sleepCtx(ctx, probeStartupDelay)
	for ctx.Err() == nil {
		runHealthProbesOnce(ctx, cfg)
		sleepCtx(ctx, probeInterval)
	}
}

func runHealthProbesOnce(ctx context.Context, cfg envConfig) {
	camouflage := probeCamouflageDest(ctx, cfg.RealityDest, cfg.CamouflageDomain)
	reality := probeRealityFallback(ctx, cfg.RealityProbeAddr, cfg.CamouflageDomain)
	currentHealth.Store(&healthState{Camouflage: &camouflage, Reality: &reality})
	if !camouflage.OK {
		slog.Warn("REALITY_DEST is not a good camouflage target", "target", camouflage.Target, "camouflage_domain", cfg.CamouflageDomain, "problem", probeProblem(camouflage))
	}
	if !reality.OK {
		slog.Warn("REALITY listener does not look like the camouflage site to a probe without a client key", "target", reality.Target, "camouflage_domain", cfg.CamouflageDomain, "problem", probeProblem(reality))
	}
}

// probeCamouflageDest checks the properties REALITY relies on: TLS 1.3 with
// X25519 and h2, and a publicly trusted certificate for the camouflage name.
// A site behind a CDN is flagged because its IP does not match the name's
// usual hosting and it may rate-limit or change certificates unexpectedly.
func probeCamouflageDest(ctx context.Context, dest, domain string) probeReport {
	report := tlsProbe(ctx, dest, domain)
	if report.OK && report.CDN != "" {
		report.OK = false
		report.Error = "certificate is issued by CDN " + report.CDN
	}
	return report
}

// probeRealityFallback connects to the REALITY listener like an active probe
// (no client key) and expects to see the camouflage site's certificate.
func probeRealityFallback(ctx context.Context, addr, domain string) probeReport {
	if strings.TrimSpace(addr) == "" {
		addr = defaultRealityAddr
	}
	return tlsProbe(ctx, addr, domain)
}

func tlsProbe(ctx context.Context, addr, serverName string) probeReport {
	report := probeReport{Target: addr, CheckedAt: time.Now().UTC()}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	started := time.Now()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: probeTimeout},
		Config: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS13,
			// Offering only X25519 makes a successful handshake prove support.
			CurvePreferences: []tls.CurveID{tls.X25519},
			NextProtos:       []string{"h2", "http/1.1"},
			RootCAs:          probeRootCAs,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	report.RTTMillis = time.Since(started).Milliseconds()
	if err != nil {
		report.Error = probeError(err)
		var verr *tls.CertificateVerificationError
		if errors.As(err, &verr) {
			// The handshake itself worked; only the certificate is wrong.
			report.TLS13, report.X25519 = true, true
		}
		return report
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	report.TLS13 = state.Version == tls.VersionTLS13
	report.X25519 = report.TLS13
	report.H2 = state.NegotiatedProtocol == "h2"
	report.CertMatches = true
	if len(state.PeerCertificates) > 0 {
		report.CDN = cdnIssuer(state.PeerCertificates[0])
	}
	report.OK = report.TLS13 && report.H2
	if !report.H2 {
		report.Error = "server did not negotiate h2"
	}
	return report
}

// probeErrorMaxLen keeps health reports inside the self_describe string limit.
const probeErrorMaxLen = 200

func probeError(err error) string {
	msg := err.Error()
	var verr *tls.CertificateVerificationError
	if errors.As(err, &verr) {
		msg = "certificate is not valid for the camouflage name: " + verr.Err.Error()
	}
	if len(msg) > probeErrorMaxLen {
		msg = strings.ToValidUTF8(msg[:probeErrorMaxLen], "")
	}
	return msg
}

func probeProblem(r probeReport) string {
	if r.Error != "" {
		return r.Error
	}
	return fmt.Sprintf("tls13=%t h2=%t x25519=%t", r.TLS13, r.H2, r.X25519)
}

func cdnIssuer(cert *x509.Certificate) string {
	issuer := strings.ToLower(strings.Join(append(cert.Issuer.Organization, cert.Issuer.CommonName), " "))
	for _, cdn := range []string{"cloudflare", "fastly", "akamai", "amazon cloudfront", "cloudfront"} {
		if strings.Contains(issuer, cdn) {
			return cdn
		}
	}
	for _, name := range cert.DNSNames {
		if strings.HasSuffix(name, ".cloudflaressl.com") || strings.HasSuffix(name, ".fastly.net") || strings.HasSuffix(name, ".akamaized.net") {
			return strings.SplitN(strings.TrimPrefix(name, "*."), ".", 2)[1]
		}
	}
	return ""
}
