package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/serverpeer"
)

func renderAll(cfg envConfig, st stateFile) error {
	if err := renderXray(cfg, st); err != nil {
		return err
	}
	if err := renderAWG(cfg, st); err != nil {
		return err
	}
	if err := renderDistributor(cfg, st); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(cfg.StateDir, "self-describe.json"), selfDescribe(cfg, st), 0o644); err != nil {
		return err
	}
	return nil
}

// renderXray brings Xray in line with the current settings and the cached
// device list at startup. It always goes through applyXrayConfig, so a
// changed .env (camouflage domain, dest, XHTTP, egress policy) reaches the
// running Xray even when there are no devices yet.
func renderXray(cfg envConfig, st stateFile) error {
	ds, cachedErr := loadCachedDesiredState(cfg.StateDir)
	var devices []approvedDevice
	if cachedErr == nil {
		devices = ds.realityDevices(platformNow())
	}
	// The same anti-wipe rule as for AWG: an unreadable cache, or an empty
	// list nobody asked for, must not remove every REALITY user.
	if orchAppliedSeq(cfg.StateDir) > 0 && (cachedErr != nil || (len(devices) == 0 && !ds.realityIntentionallyEmpty())) {
		slog.Warn("xray render skipped by anti-wipe guard", "err", cachedErr)
		return nil
	}
	xrayRaw, err := xrayConfigBytes(cfg, st, devices)
	if errors.Is(err, errNoShortIDs) {
		// Keep whatever Xray runs now rather than a config it rejects.
		slog.Error("xray config not rendered; keeping the last valid one", "err", err)
		return nil
	}
	if err != nil {
		return err
	}
	return applyXrayConfig(cfg, xrayRaw, len(devices))
}

func renderAWG(cfg envConfig, st stateFile) error {
	ds, cachedErr := loadCachedDesiredState(cfg.StateDir)
	var devices []approvedDevice
	skipRegistryWrite := false
	if cachedErr != nil {
		if orchAppliedSeq(cfg.StateDir) > 0 {
			slog.Warn("awg registry render skipped by anti-wipe guard", "err", cachedErr)
			skipRegistryWrite = true
		}
	} else {
		devices = ds.awgDevices(platformNow())
		if orchAppliedSeq(cfg.StateDir) > 0 && len(devices) == 0 && !ds.awgIntentionallyEmpty() {
			slog.Warn("awg registry render skipped by anti-wipe guard: applied worker config has no approved devices")
			skipRegistryWrite = true
		}
	}
	for _, profile := range awgProfiles(cfg) {
		addr := profile.Gateway + "/" + prefixLen(profile.Subnet)
		awgCfg := serverpeer.GatewayConfig{
			Interface:       profile.Interface,
			Address:         addr,
			ListenPort:      profile.ListenPort,
			PrivateKeyHex:   st.AWG.PrivateKeyHex,
			PublicKey:       st.AWG.PublicKey,
			Dialect:         profileDialect(st, profile),
			PeerRegistry:    profile.registryPath(cfg.StateDir),
			ServerKeepalive: cfg.AWGServerKeepalive,
			WorkerAddresses: workerAddresses(cfg),
		}
		if err := writeJSONFile(profile.configPath(cfg.StateDir), awgCfg, 0o600); err != nil {
			return err
		}
		if !skipRegistryWrite {
			if _, err := writeAWGPeerRegistryForProfile(cfg, st, devices, profile); err != nil {
				return err
			}
		}
	}
	return writeFile(filepath.Join(cfg.StateDir, "smoke", "awg-peer.conf"), []byte(smokePeerConfig(cfg, st)), 0o600)
}

func renderDistributor(cfg envConfig, st stateFile) error {
	if err := ensureDistributorCert(cfg); err != nil {
		return err
	}
	if orchAppliedSeq(cfg.StateDir) > 0 && fileExists(filepath.Join(cfg.StateDir, "distributor", "tw", "config.json")) {
		return nil
	}
	if loadOrchState(cfg.StateDir).Status == orchStatusRevoked {
		return nil
	}
	pubCfg := map[string]any{
		"worker":      selfDescribe(cfg, st),
		"placeholder": true,
		"note":        "P0 distributor placeholder; client-specific secrets are not published here",
	}
	if err := writeJSONFile(filepath.Join(cfg.StateDir, "distributor", "tw", "config.json"), pubCfg, 0o644); err != nil {
		return err
	}
	version := map[string]any{"version": "p0", "created_at": time.Now().UTC().Format(time.RFC3339), "apk": "placeholder.apk"}
	if err := writeJSONFile(filepath.Join(cfg.StateDir, "distributor", "tw", "version.json"), version, 0o644); err != nil {
		return err
	}
	return writeFile(filepath.Join(cfg.StateDir, "distributor", "tw", "placeholder.apk"), []byte("TrafficWrapper P0 placeholder APK\n"), 0o644)
}

const distributorCertRenewBefore = 30 * 24 * time.Hour

// ensureDistributorCert (re)issues the distributor certificate when it is
// missing, unreadable, close to expiry or issued for another name. The
// distributor entrypoint reloads nginx when the files change.
func ensureDistributorCert(cfg envConfig) error {
	certPath := filepath.Join(cfg.StateDir, "distributor", "certs", "tls.crt")
	keyPath := filepath.Join(cfg.StateDir, "distributor", "certs", "tls.key")
	if fileExists(keyPath) && !distributorCertNeedsRenewal(certPath, cfg.CamouflageDomain, time.Now()) {
		return nil
	}
	cert, key, err := selfSignedCert(cfg.CamouflageDomain)
	if err != nil {
		return err
	}
	if err := writeFile(keyPath, key, 0o600); err != nil {
		return err
	}
	if err := writeFile(certPath, cert, 0o600); err != nil {
		return err
	}
	slog.Info("distributor certificate issued", "camouflage_domain", cfg.CamouflageDomain)
	return nil
}

func distributorCertNeedsRenewal(certPath, name string, now time.Time) bool {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	if cert.VerifyHostname(name) != nil {
		return true
	}
	return now.Add(distributorCertRenewBefore).After(cert.NotAfter)
}

func runDistributorCertRenewal(ctx context.Context, cfg envConfig) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ensureDistributorCert(cfg); err != nil {
				slog.Error("distributor certificate renewal failed", "err", err)
			}
		}
	}
}

func orchAppliedSeq(stateDir string) int64 {
	raw, err := os.ReadFile(filepath.Join(stateDir, "orch", "state.json"))
	if err != nil {
		return 0
	}
	var state struct {
		AppliedSeq int64 `json:"applied_seq"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return 0
	}
	return state.AppliedSeq
}

func selfSignedCert(name string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyRaw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyRaw})
	return certPEM, keyPEM, nil
}

func smokePeerConfig(cfg envConfig, st stateFile) string {
	profile := baseAWGProfile(cfg)
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = %s/32
PersistentKeepalive = 25

# AmneziaWG dialect: jc=%d jmin=%d jmax=%d s1=%d s2=%d s3=%d s4=%d h1=%s h2=%s h3=%s h4=%s
`, st.AWG.SmokePrivate, st.AWG.SmokeIP, st.AWG.PublicKey, st.AWG.SmokePSK,
		net.JoinHostPort(cfg.PublicAddress, strconv.Itoa(profile.PublicPort)), profile.Gateway,
		st.Dialect.Jc, st.Dialect.Jmin, st.Dialect.Jmax, st.Dialect.S1, st.Dialect.S2,
		st.Dialect.S3, st.Dialect.S4, st.Dialect.H1, st.Dialect.H2, st.Dialect.H3, st.Dialect.H4)
}

func firstHost(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	if !addr.Is4() {
		return "", errors.New("AWG_SUBNET must be IPv4")
	}
	gateway := addr.Next()
	if !gateway.IsValid() || !prefix.Contains(gateway) {
		return "", fmt.Errorf("subnet %s has no usable host", prefix)
	}
	return gateway.String(), nil
}

func secondHostCIDR(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return "10.13.13.2/32"
	}
	prefix = prefix.Masked()
	host := prefix.Addr().Next().Next()
	if !host.IsValid() || !prefix.Contains(host) {
		return "10.13.13.2/32"
	}
	return host.String() + "/32"
}

func prefixLen(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "24"
	}
	return strconv.Itoa(prefix.Bits())
}
