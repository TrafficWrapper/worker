package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/TrafficWrapper/worker/agent/internal/bundle"
	"github.com/TrafficWrapper/worker/agent/internal/protocol"
	"github.com/TrafficWrapper/worker/core/awg/dialect"
)

const (
	stateDirDefault       = "/worker-state"
	xrayInPort            = 8443
	awgInPort             = 51821
	distributorTLS        = 9443
	distributorTW         = 8080
	telemetryMaxBodyBytes = 64 << 10
)

type stateFile struct {
	CreatedAt        time.Time            `json:"created_at"`
	Hostname         string               `json:"hostname"`
	EgressIP         string               `json:"egress_ip"`
	Reality          realityState         `json:"reality"`
	AWG              awgState             `json:"awg"`
	Dialect          dialect.Dialect      `json:"dialect"`
	DialectID        string               `json:"dialect_id"`
	NoiseStatic      protocol.KeyPairFile `json:"noise_static"`
	EnrollTokenHash  string               `json:"enroll_token_hash,omitempty"`
	SmokeRealityUUID string               `json:"smoke_reality_uuid"`
}

type realityState struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
}

type awgState struct {
	PrivateKeyHex string `json:"private_key_hex"`
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	SmokePrivate  string `json:"smoke_private_key"`
	SmokePublic   string `json:"smoke_public_key"`
	SmokePSK      string `json:"smoke_psk"`
	SmokeIP       string `json:"smoke_ip"`
}

type envConfig struct {
	StateDir         string
	XrayPort         int
	AWGPort          int
	AWGSubnet        string
	AWGGateway       string
	AWGUAPISocket    string
	XrayContainer    string
	DockerSocket     string
	OrchURL          string
	OrchStaticPublic string
	OrchInsecureTLS  bool
	WorkerAgentURL   string
	CamouflageDomain string
	RealityDest      string
	EgressIP         string
	PublicAddress    string
	DistributorURL   string
	EnrollToken      string
	Capacity         int
}

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	cfg, err := readEnv()
	if err != nil {
		fatal(err)
	}
	switch cmd {
	case "run":
		if err := run(cfg); err != nil {
			fatal(err)
		}
	case "bootstrap":
		_, err := bootstrap(cfg)
		if err != nil {
			fatal(err)
		}
	case "self-describe":
		st, err := loadBootstrapState(cfg.StateDir)
		if errors.Is(err, os.ErrNotExist) {
			st, err = bootstrap(cfg)
		}
		if err != nil {
			fatal(err)
		}
		_ = encodeJSON(os.Stdout, selfDescribe(cfg, st))
	case "check-dialect":
		if err := checkDialectFromEnv(); err != nil {
			fatal(err)
		}
	case "show-awg-peers":
		peers, err := listAWGPeerConfigs(cfg.AWGUAPISocket)
		if err != nil {
			fatal(err)
		}
		_ = encodeJSON(os.Stdout, peers)
	default:
		fatal(fmt.Errorf("unknown command %q", cmd))
	}
}

func run(cfg envConfig) error {
	st, err := bootstrap(cfg)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/self-describe", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, selfDescribe(cfg, st))
	})
	mux.HandleFunc("/enroll", standaloneStub("enroll", cfg))
	mux.HandleFunc("/pull", standaloneStub("pull", cfg))
	mux.HandleFunc("/nudge", standaloneStub("nudge", cfg))
	mux.HandleFunc("/ack", standaloneStub("ack", cfg))
	mux.HandleFunc("/orchestrator/apply-discovery", applyDiscoveryHandler)
	mux.HandleFunc("/orchestrator/verify-minisign", verifyMinisignHandler)
	mux.HandleFunc("/orchestrator/telemetry", telemetryHandler(cfg, st))
	// Compose publishes the agent port on host loopback by default; keep /metrics
	// on this local agent surface because peer labels expose public keys/endpoints.
	mux.HandleFunc("/metrics", metricsHandler(cfg, time.Now()))

	srv := &http.Server{Addr: ":9090", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if cfg.OrchURL != "" {
		go runOrchestratorLoop(ctx, cfg, st)
	}
	log.Printf("worker-agent standalone=%t self_describe=:9090/self-describe orch_url=%q", cfg.OrchURL == "", cfg.OrchURL)
	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func telemetryHandler(cfg envConfig, st stateFile) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(r.Body, telemetryMaxBodyBytes+1))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(raw) == 0 || len(raw) > telemetryMaxBodyBytes || !json.Valid(raw) {
			http.Error(w, "invalid telemetry payload", http.StatusBadRequest)
			return
		}
		state := loadOrchState(cfg.StateDir)
		if state.WorkerID == "" {
			http.Error(w, "worker is not enrolled", http.StatusServiceUnavailable)
			return
		}
		client, err := newOrchClient(cfg, st)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		headers := telemetryHeadersFromRequest(r)
		if err := client.telemetry(state.WorkerID, raw, headers); err != nil {
			log.Printf("telemetry forward failed: %v", err)
			http.Error(w, "telemetry forward failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func telemetryHeadersFromRequest(r *http.Request) map[string]string {
	headers := map[string]string{}
	for _, name := range []string{
		"X-TW-Device",
		"X-TW-Pub",
		"X-TW-KeyType",
		"X-TW-Ts",
		"X-TW-Nonce",
		"X-TW-Sig",
	} {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			headers[name] = value
		}
	}
	return headers
}

func readEnv() (envConfig, error) {
	subnet := getenv("AWG_SUBNET", "10.13.13.0/24")
	gateway, err := firstHost(subnet)
	if err != nil {
		return envConfig{}, err
	}
	cfg := envConfig{
		StateDir:         getenv("WORKER_STATE_DIR", stateDirDefault),
		XrayPort:         getenvInt("XRAY_PORT", 2053),
		AWGPort:          getenvInt("AWG_PORT", 51888),
		AWGSubnet:        subnet,
		AWGGateway:       getenv("AWG_GATEWAY", gateway),
		AWGUAPISocket:    getenv("AWG_UAPI_SOCKET", "/var/run/wireguard/awg1.sock"),
		XrayContainer:    os.Getenv("XRAY_CONTAINER_NAME"),
		DockerSocket:     getenv("DOCKER_SOCKET", "/var/run/docker.sock"),
		OrchURL:          os.Getenv("ORCH_URL"),
		OrchStaticPublic: os.Getenv("ORCH_STATIC_PUBLIC_KEY"),
		OrchInsecureTLS:  getenv("ORCH_INSECURE_TLS", "0") == "1",
		WorkerAgentURL:   os.Getenv("WORKER_AGENT_URL"),
		CamouflageDomain: os.Getenv("CAMOUFLAGE_DOMAIN"),
		RealityDest:      getenv("REALITY_DEST", fmt.Sprintf("awg-gw:%d", distributorTLS)),
		EgressIP:         os.Getenv("EGRESS_IP"),
		PublicAddress:    os.Getenv("PUBLIC_ADDRESS"),
		DistributorURL:   getenv("DISTRIBUTOR_URL", fmt.Sprintf("http://awg-gw:%d/tw", distributorTW)),
		EnrollToken:      os.Getenv("ENROLL_TOKEN"),
		Capacity:         getenvInt("CAPACITY", 32),
	}
	if cfg.EgressIP == "" {
		cfg.EgressIP = detectPublicEgressIP()
	}
	if cfg.EgressIP == "" {
		cfg.EgressIP = outboundIP()
	}
	if cfg.PublicAddress == "" {
		cfg.PublicAddress = cfg.EgressIP
	}
	if err := validateCamouflageDomain(cfg.CamouflageDomain); err != nil {
		return envConfig{}, err
	}
	return cfg, nil
}

func validateCamouflageDomain(domain string) error {
	switch strings.ToLower(strings.TrimSpace(domain)) {
	case "", "example.com", "example.org":
		return errors.New("refusing placeholder CAMOUFLAGE_DOMAIN; set a real TLS1.3 domain")
	default:
		return nil
	}
}

func bootstrap(cfg envConfig) (stateFile, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return stateFile{}, err
	}
	path := filepath.Join(cfg.StateDir, "bootstrap.json")
	if raw, err := os.ReadFile(path); err == nil {
		var st stateFile
		if err := json.Unmarshal(raw, &st); err != nil {
			return stateFile{}, fmt.Errorf("parse bootstrap state: %w", err)
		}
		var err error
		st, err = reconcileBootstrapEgress(path, cfg, st)
		if err != nil {
			return stateFile{}, err
		}
		if err := renderAll(cfg, st); err != nil {
			return stateFile{}, err
		}
		return st, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return stateFile{}, err
	}

	d, err := workerDialect()
	if err != nil {
		return stateFile{}, err
	}
	dialectID, err := dialectHash(d)
	if err != nil {
		return stateFile{}, err
	}
	realityPrivate, realityPublic, err := x25519RawURLEncoded()
	if err != nil {
		return stateFile{}, err
	}
	awgPrivateHex, awgPrivate, awgPublic, err := wgKeypair()
	if err != nil {
		return stateFile{}, err
	}
	smokePrivateHex, smokePrivate, smokePublic, err := wgKeypair()
	if err != nil {
		return stateFile{}, err
	}
	_ = smokePrivateHex
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return stateFile{}, err
	}
	noiseKey, err := protocol.GenerateKeypair()
	if err != nil {
		return stateFile{}, err
	}
	enrollHash := ""
	if cfg.EnrollToken != "" {
		enrollHash, err = protocol.HashSecret(cfg.EnrollToken)
		if err != nil {
			return stateFile{}, err
		}
	}
	host, _ := os.Hostname()
	st := stateFile{
		CreatedAt: time.Now().UTC(),
		Hostname:  host,
		EgressIP:  cfg.EgressIP,
		Reality: realityState{
			PrivateKey: realityPrivate,
			PublicKey:  realityPublic,
			ShortID:    randHex(8),
		},
		AWG: awgState{
			PrivateKeyHex: awgPrivateHex,
			PrivateKey:    awgPrivate,
			PublicKey:     awgPublic,
			SmokePrivate:  smokePrivate,
			SmokePublic:   smokePublic,
			SmokePSK:      base64.StdEncoding.EncodeToString(psk),
			SmokeIP:       secondHostCIDR(cfg.AWGSubnet),
		},
		Dialect:          d,
		DialectID:        dialectID,
		NoiseStatic:      protocol.NewKeyPairFile(noiseKey),
		EnrollTokenHash:  enrollHash,
		SmokeRealityUUID: uuidV4(),
	}
	if err := writeJSONFile(path, st, 0o600); err != nil {
		return stateFile{}, err
	}
	if err := renderAll(cfg, st); err != nil {
		return stateFile{}, err
	}
	return st, nil
}

func reconcileBootstrapEgress(path string, cfg envConfig, st stateFile) (stateFile, error) {
	if cfg.EgressIP == "" || st.EgressIP == cfg.EgressIP {
		return st, nil
	}
	st.EgressIP = cfg.EgressIP
	if err := writeJSONFile(path, st, 0o600); err != nil {
		return stateFile{}, err
	}
	return st, nil
}

func loadBootstrapState(stateDir string) (stateFile, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "bootstrap.json"))
	if err != nil {
		return stateFile{}, err
	}
	var st stateFile
	if err := json.Unmarshal(raw, &st); err != nil {
		return stateFile{}, fmt.Errorf("parse bootstrap state: %w", err)
	}
	return st, nil
}

func workerDialect() (dialect.Dialect, error) {
	if raw := strings.TrimSpace(os.Getenv("TW_WORKER_DIALECT_JSON")); raw != "" {
		var d dialect.Dialect
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			return dialect.Dialect{}, fmt.Errorf("parse TW_WORKER_DIALECT_JSON: %w", err)
		}
		if dialect.IsCompat(d) {
			return dialect.Dialect{}, errors.New("refusing example/compat AWG dialect")
		}
		if err := dialect.ValidateProduction(d, dialect.DefaultMTU); err != nil {
			return dialect.Dialect{}, err
		}
		return d, nil
	}
	d, err := dialect.Generate()
	if err != nil {
		return dialect.Dialect{}, err
	}
	if dialect.IsCompat(d) {
		return dialect.Dialect{}, errors.New("refusing generated compat AWG dialect")
	}
	return d, nil
}

func checkDialectFromEnv() error {
	_, err := workerDialect()
	return err
}

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

func renderXray(cfg envConfig, st stateFile) error {
	devices := filterUnexpiredApprovedDevices(cachedApprovedDevices(cfg.StateDir), time.Now().UTC())
	xrayRaw, err := xrayConfigBytes(cfg, st, devices)
	if err != nil {
		return err
	}
	if len(devices) == 0 && !xrayRestartPending(cfg) {
		if !xrayConfigChanged(cfg, xrayRaw) {
			return nil
		}
		return writeXrayConfigBytes(cfg, xrayRaw)
	}
	return applyXrayConfigWithRestart(cfg, xrayRaw, len(devices), 0)
}

func xrayConfigDocument(cfg envConfig, st stateFile, devices []approvedDevice) map[string]any {
	clients := []any{map[string]any{
		"id":    st.SmokeRealityUUID,
		"email": "p0-smoke",
	}}
	seen := map[string]struct{}{st.SmokeRealityUUID: {}}
	for _, device := range devices {
		if device.Status != "approved" || device.RealityUUID == "" {
			continue
		}
		if _, ok := seen[device.RealityUUID]; ok {
			continue
		}
		seen[device.RealityUUID] = struct{}{}
		email := device.DeviceID
		if email == "" {
			email = "device"
		}
		clients = append(clients, map[string]any{
			"id":    device.RealityUUID,
			"email": email,
		})
	}
	xcfg := map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"tag":      "reality-in",
			"listen":   "0.0.0.0",
			"port":     xrayInPort,
			"protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    clients,
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"show":        false,
					"dest":        cfg.RealityDest,
					"xver":        0,
					"serverNames": []string{cfg.CamouflageDomain},
					"privateKey":  st.Reality.PrivateKey,
					"shortIds":    []string{st.Reality.ShortID},
				},
			},
		}},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
	}
	return xcfg
}

func writeXrayConfig(cfg envConfig, st stateFile, devices []approvedDevice) (bool, error) {
	raw, err := xrayConfigBytes(cfg, st, devices)
	if err != nil {
		return false, err
	}
	if !xrayConfigChanged(cfg, raw) {
		return false, nil
	}
	return true, writeXrayConfigBytes(cfg, raw)
}

func xrayConfigBytes(cfg envConfig, st stateFile, devices []approvedDevice) ([]byte, error) {
	raw, err := json.MarshalIndent(xrayConfigDocument(cfg, st, devices), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func xrayConfigChanged(cfg envConfig, raw []byte) bool {
	old, _ := os.ReadFile(xrayConfigPath(cfg))
	return string(old) != string(raw)
}

func writeXrayConfigBytes(cfg envConfig, raw []byte) error {
	return writeFile(xrayConfigPath(cfg), raw, 0o600)
}

func xrayConfigPath(cfg envConfig) string {
	return filepath.Join(cfg.StateDir, "xray", "config.json")
}

func xrayRestartPendingPath(cfg envConfig) string {
	return filepath.Join(cfg.StateDir, "xray", "restart-pending")
}

func xrayRestartPending(cfg envConfig) bool {
	_, err := os.Stat(xrayRestartPendingPath(cfg))
	return err == nil
}

func markXrayRestartPending(cfg envConfig) error {
	return writeFile(xrayRestartPendingPath(cfg), []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600)
}

func clearXrayRestartPending(cfg envConfig) error {
	err := os.Remove(xrayRestartPendingPath(cfg))
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func renderAWG(cfg envConfig, st stateFile) error {
	addr := cfg.AWGGateway + "/" + prefixLen(cfg.AWGSubnet)
	awgCfg := map[string]any{
		"interface":       "awg1",
		"address":         addr,
		"listen_port":     awgInPort,
		"private_key_hex": st.AWG.PrivateKeyHex,
		"public_key":      st.AWG.PublicKey,
		"dialect":         st.Dialect,
		"peer_registry":   "/worker-state/awg/peers.json",
	}
	if err := writeJSONFile(filepath.Join(cfg.StateDir, "awg", "awg-gw.json"), awgCfg, 0o600); err != nil {
		return err
	}
	if _, err := writeAWGPeerRegistry(cfg, st, filterUnexpiredApprovedDevices(cachedApprovedDevices(cfg.StateDir), time.Now().UTC())); err != nil {
		return err
	}
	return writeFile(filepath.Join(cfg.StateDir, "smoke", "awg-peer.conf"), []byte(smokePeerConfig(cfg, st)), 0o600)
}

func renderDistributor(cfg envConfig, st stateFile) error {
	certPath := filepath.Join(cfg.StateDir, "distributor", "certs", "tls.crt")
	keyPath := filepath.Join(cfg.StateDir, "distributor", "certs", "tls.key")
	if !fileExists(certPath) || !fileExists(keyPath) {
		cert, key, err := selfSignedCert(cfg.CamouflageDomain)
		if err != nil {
			return err
		}
		if err := writeFile(certPath, cert, 0o600); err != nil {
			return err
		}
		if err := writeFile(keyPath, key, 0o600); err != nil {
			return err
		}
	}
	if orchAppliedSeq(cfg.StateDir) > 0 && fileExists(filepath.Join(cfg.StateDir, "distributor", "tw", "config.json")) {
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

func selfDescribe(cfg envConfig, st stateFile) map[string]any {
	out := map[string]any{
		"schema":          "trafficwrapper-worker-p0",
		"hostname":        st.Hostname,
		"egress_ip":       cfg.EgressIP,
		"orch_url":        cfg.OrchURL,
		"agent_url":       cfg.WorkerAgentURL,
		"distributor_url": cfg.DistributorURL,
		"standalone":      cfg.OrchURL == "",
		"dialect_id":      st.DialectID,
		"capacity":        cfg.Capacity,
		"protocols":       []string{"REALITY", "AWG"},
		"reality": map[string]any{
			"transport":   "REALITY",
			"address":     cfg.PublicAddress,
			"port":        cfg.XrayPort,
			"serverName":  cfg.CamouflageDomain,
			"server_name": cfg.CamouflageDomain,
			"dest":        cfg.RealityDest,
			"publicKey":   st.Reality.PublicKey,
			"public_key":  st.Reality.PublicKey,
			"shortId":     st.Reality.ShortID,
			"short_id":    st.Reality.ShortID,
			"flow":        "",
			"security":    "reality",
			"network":     "tcp",
			"fingerprint": "chrome",
			"spiderX":     "/",
		},
		"awg": map[string]any{
			"address":           cfg.PublicAddress,
			"endpoint":          net.JoinHostPort(cfg.PublicAddress, strconv.Itoa(cfg.AWGPort)),
			"public_key":        st.AWG.PublicKey,
			"server_public":     st.AWG.PublicKey,
			"server_public_key": st.AWG.PublicKey,
			"port":              cfg.AWGPort,
			"subnet":            cfg.AWGSubnet,
			"gateway":           cfg.AWGGateway,
			"dialect":           st.Dialect,
			"dialect_id":        st.DialectID,
			"smoke_peer_config": "/worker-state/smoke/awg-peer.conf",
		},
		"orchestrator": map[string]any{
			"noise_xk_ready":  true,
			"pull_ready":      true,
			"nudge_ack_ready": true,
			"max_seen_seq":    0,
		},
	}
	if apk := distributedAPKInfo(cfg.StateDir); len(apk) > 0 {
		out["distributed_apk"] = apk
	}
	return out
}

func distributedAPKInfo(stateDir string) map[string]any {
	twDir := filepath.Join(stateDir, "distributor", "tw")
	for _, path := range []string{
		filepath.Join(twDir, "update-manifest.json"),
		filepath.Join(twDir, "version.json"),
	} {
		raw, err := os.ReadFile(path)
		if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		var root map[string]any
		if err := json.Unmarshal(raw, &root); err != nil {
			continue
		}
		if nested, ok := root["distributed_apk"].(map[string]any); ok {
			root = nested
		}
		apk := map[string]any{}
		if v := stringFromAny(root["apk_sha256"]); v != "" {
			apk["apk_sha256"] = strings.ToLower(v)
		}
		if v := int64FromAny(root["version_code"]); v > 0 {
			apk["version_code"] = v
		}
		if v := stringFromAny(root["version_name"]); v != "" {
			apk["version_name"] = v
		}
		if v := stringFromAny(root["apk_name"]); v != "" {
			apk["apk_name"] = filepath.Base(v)
		}
		if len(apk) > 0 {
			return apk
		}
	}
	return nil
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

func int64FromAny(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		out, _ := v.Int64()
		return out
	default:
		return 0
	}
}

func standaloneStub(action string, cfg envConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		status := map[string]any{"ok": true, "action": action, "standalone": cfg.OrchURL == ""}
		if cfg.OrchURL == "" {
			status["message"] = "ORCH_URL is empty; P0 standalone mode"
		}
		writeJSON(w, status)
	}
}

func applyDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(req)
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write([]byte(bundle.ApplyDiscoveredEndpoints(string(raw))))
}

func verifyMinisignHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write([]byte(bundle.VerifyMinisign(req.Message, req.Signature, req.PublicKey)))
}

func wgKeypair() (privateHex, privateB64, publicB64 string, err error) {
	priv := make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return "", "", "", err
	}
	clamp(priv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", "", err
	}
	return hex.EncodeToString(priv), base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

func x25519RawURLEncoded() (privateKey, publicKey string, err error) {
	priv := make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return "", "", err
	}
	clamp(priv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv), base64.RawURLEncoding.EncodeToString(pub), nil
}

func clamp(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

func dialectHash(d dialect.Dialect) (string, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:12]), nil
}

func sha256HexBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func uuidV4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
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
		net.JoinHostPort(cfg.PublicAddress, strconv.Itoa(cfg.AWGPort)), cfg.AWGGateway,
		st.Dialect.Jc, st.Dialect.Jmin, st.Dialect.Jmax, st.Dialect.S1, st.Dialect.S2,
		st.Dialect.S3, st.Dialect.S4, st.Dialect.H1, st.Dialect.H2, st.Dialect.H3, st.Dialect.H4)
}

func firstHost(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	addr := prefix.Addr()
	if !addr.Is4() {
		return "", errors.New("AWG_SUBNET must be IPv4")
	}
	raw := addr.As4()
	raw[3]++
	return netip.AddrFrom4(raw).String(), nil
}

func secondHostCIDR(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "10.13.13.2/32"
	}
	raw := prefix.Addr().As4()
	raw[3] += 2
	return netip.AddrFrom4(raw).String() + "/32"
}

func prefixLen(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "24"
	}
	return strconv.Itoa(prefix.Bits())
}

func outboundIP() string {
	c, err := net.DialTimeout("udp", "1.1.1.1:53", time.Second)
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return "127.0.0.1"
	}
	return host
}

func detectPublicEgressIP() string {
	for _, url := range []string{"https://api.ipify.org", "https://ifconfig.co/ip", "https://ipinfo.io/ip"} {
		client := http.Client{Timeout: 4 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			continue
		}
		ip := strings.TrimSpace(string(raw))
		if isPublicIP(ip) {
			return ip
		}
	}
	return ""
}

func isPublicIP(value string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast()
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("content-type", "application/json")
	_ = encodeJSON(w, value)
}

func encodeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func writeJSONFile(path string, value any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFile(path, raw, mode)
}

func writeFile(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fatal(err error) {
	log.Printf("worker-agent: %v", err)
	os.Exit(1)
}
