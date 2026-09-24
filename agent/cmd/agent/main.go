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
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/TrafficWrapper/worker/agent/internal/protocol"
	"github.com/TrafficWrapper/worker/core/awg/dialect"
)

const (
	stateDirDefault       = "/worker-state"
	xrayInPort            = 8443
	xrayAPIInPort         = 10085
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
	PrivateKey     string   `json:"private_key"`
	PublicKey      string   `json:"public_key"`
	ShortID        string   `json:"short_id"`
	CohortShortIDs []string `json:"cohort_short_ids,omitempty"`
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
	StateDir               string
	XrayPort               int
	AWGPort                int
	AWGSubnet              string
	AWGGateway             string
	AWGUAPISocket          string
	AWGServerKeepalive     int
	AWGProfiles            []awgInboundProfile
	MetricsScrubPeerLabels bool
	MetricsScrubSalt       string
	XrayContainer          string
	DockerSocket           string
	OrchURL                string
	OrchStaticPublic       string
	OrchInsecureTLS        bool
	WorkerAgentURL         string
	CamouflageDomain       string
	RealityDest            string
	XrayNetwork            string
	XHTTPPath              string
	XHTTPMode              string
	XHTTPHost              string
	XHTTPExtraJSON         string
	EgressIP               string
	PublicAddress          string
	DistributorURL         string
	EnrollToken            string
	Capacity               int
	DisableSmokePeers      bool
	AllowPrivateEgress     bool
	OrchAckInterval        time.Duration
	RealityProbeAddr       string
	RealityProfiles        []realityProfile
	BlockSMTP              bool
	BlockBitTorrent        bool
}

type awgInboundProfile struct {
	Name           string `json:"name"`
	Interface      string `json:"interface"`
	ListenPort     int    `json:"listen_port"`
	PublicPort     int    `json:"public_port,omitempty"`
	Subnet         string `json:"subnet"`
	Gateway        string `json:"gateway,omitempty"`
	UAPISocket     string `json:"uapi_socket,omitempty"`
	MinVersionCode int    `json:"min_version_code,omitempty"`
}

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd == "healthcheck" {
		if err := runHealthcheck(getenv("AGENT_HEALTH_URL", "http://127.0.0.1:9090/healthz")); err != nil {
			fatal(err)
		}
		return
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
		if err != nil {
			fatal(err)
		}
		_ = encodeJSON(os.Stdout, selfDescribe(cfg, st))
	case "check-dialect":
		if err := checkDialectFromEnv(); err != nil {
			fatal(err)
		}
	case "show-awg-peers":
		_ = encodeJSON(os.Stdout, collectAWGProfilePeerSnapshots(cfg))
	default:
		fatal(fmt.Errorf("unknown command %q", cmd))
	}
}

func runHealthcheck(url string) error {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck %s: http %d", url, resp.StatusCode)
	}
	return nil
}

func run(cfg envConfig) error {
	st, err := bootstrap(cfg)
	if err != nil {
		return err
	}
	var orch *orchClient
	if cfg.OrchURL != "" {
		if orch, err = prepareOrchestrator(cfg, st); err != nil {
			return err
		}
	}
	if cfg.OrchURL == "" {
		log.Printf("awg reconcile standalone mode: startup pass is best-effort and no periodic orchestrator pass will run")
	}
	if err := reconcileAWGPeers(cfg, st); err != nil {
		log.Printf("awg startup reconcile incomplete: %v", err)
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
	mux.HandleFunc("/orchestrator/telemetry", telemetryHandler(cfg, st))
	// Compose publishes the agent port on host loopback by default; keep /metrics
	// on this local agent surface because peer labels expose public keys/endpoints.
	mux.HandleFunc("/metrics", metricsHandler(cfg, time.Now()))

	srv := &http.Server{
		Addr:              ":9090",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	go runDistributorCertRenewal(ctx, cfg)
	go runHealthProbes(ctx, cfg)
	if cfg.OrchURL != "" {
		go runOrchestratorLoop(ctx, cfg, st, orch)
	}
	log.Printf("worker-agent standalone=%t self_describe=:9090/self-describe orch_url=%q", cfg.OrchURL == "", cfg.OrchURL)
	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func telemetryHandler(cfg envConfig, st stateFile) http.HandlerFunc {
	// One client for the handler's lifetime keeps the HTTPS connection to the
	// orchestrator alive between telemetry posts.
	var (
		clientMu sync.Mutex
		cached   telemetryClient
	)
	getClient := func() (telemetryClient, error) {
		clientMu.Lock()
		defer clientMu.Unlock()
		if cached != nil {
			return cached, nil
		}
		client, err := newTelemetryClient(cfg, st)
		if err != nil {
			return nil, err
		}
		cached = client
		return cached, nil
	}
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
		client, err := getClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		headers := telemetryHeadersFromRequest(r)
		if err := client.telemetry(state.WorkerID, raw, headers); err != nil {
			if isDeviceNotApprovedError(err) {
				log.Printf("telemetry forward rejected: device is not approved")
				writeDeviceNotApprovedResponse(w)
				return
			}
			log.Printf("telemetry forward failed: %v", err)
			http.Error(w, "telemetry forward failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type telemetryClient interface {
	telemetry(workerID string, payload []byte, headers map[string]string) error
}

var newTelemetryClient = func(cfg envConfig, st stateFile) (telemetryClient, error) {
	return newOrchClient(cfg, st)
}

func isDeviceNotApprovedError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "device is not approved")
}

func writeDeviceNotApprovedResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"device_not_approved"}`))
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
	serverKeepalive, err := getenvIntInRange("AWG_SERVER_KEEPALIVE", 0, 0, 65535)
	if err != nil {
		return envConfig{}, err
	}
	xrayPort, err := getenvIntInRange("XRAY_PORT", 2053, 1, 65535)
	if err != nil {
		return envConfig{}, err
	}
	awgPort, err := getenvIntInRange("AWG_PORT", 51888, 1, 65535)
	if err != nil {
		return envConfig{}, err
	}
	capacity, err := getenvIntInRange("CAPACITY", 32, 1, 1<<20)
	if err != nil {
		return envConfig{}, err
	}
	cfg := envConfig{
		StateDir:               getenv("WORKER_STATE_DIR", stateDirDefault),
		XrayPort:               xrayPort,
		AWGPort:                awgPort,
		AWGSubnet:              subnet,
		AWGGateway:             getenv("AWG_GATEWAY", gateway),
		AWGUAPISocket:          getenv("AWG_UAPI_SOCKET", "/var/run/wireguard/awg1.sock"),
		AWGServerKeepalive:     serverKeepalive,
		MetricsScrubPeerLabels: getenv("TW_METRICS_SCRUB_PEER_LABELS", "0") == "1",
		XrayContainer:          os.Getenv("XRAY_CONTAINER_NAME"),
		DockerSocket:           getenv("DOCKER_SOCKET", "/var/run/docker.sock"),
		OrchURL:                os.Getenv("ORCH_URL"),
		OrchStaticPublic:       os.Getenv("ORCH_STATIC_PUBLIC_KEY"),
		OrchInsecureTLS:        getenv("ORCH_INSECURE_TLS", "0") == "1",
		WorkerAgentURL:         os.Getenv("WORKER_AGENT_URL"),
		CamouflageDomain:       os.Getenv("CAMOUFLAGE_DOMAIN"),
		RealityDest:            os.Getenv("REALITY_DEST"),
		XrayNetwork:            getenv("XRAY_NETWORK", "tcp"),
		XHTTPPath:              os.Getenv("XRAY_XHTTP_PATH"),
		XHTTPMode:              os.Getenv("XRAY_XHTTP_MODE"),
		XHTTPHost:              os.Getenv("XRAY_XHTTP_HOST"),
		XHTTPExtraJSON:         os.Getenv("XRAY_XHTTP_EXTRA_JSON"),
		EgressIP:               os.Getenv("EGRESS_IP"),
		PublicAddress:          os.Getenv("PUBLIC_ADDRESS"),
		DistributorURL:         getenv("DISTRIBUTOR_URL", fmt.Sprintf("http://awg-gw:%d/tw", distributorTW)),
		EnrollToken:            os.Getenv("ENROLL_TOKEN"),
		Capacity:               capacity,
	}
	if cfg.OrchURL != "" && strings.TrimSpace(cfg.OrchStaticPublic) == "" {
		return envConfig{}, errors.New("ORCH_URL is set but ORCH_STATIC_PUBLIC_KEY is empty")
	}
	switch getenv("WORKER_SMOKE_PEERS", "") {
	case "":
		cfg.DisableSmokePeers = cfg.OrchURL != ""
	case "1":
		cfg.DisableSmokePeers = false
	case "0":
		cfg.DisableSmokePeers = true
	default:
		return envConfig{}, errors.New("WORKER_SMOKE_PEERS must be 0 or 1")
	}
	cfg.AllowPrivateEgress = getenv("WORKER_ALLOW_PRIVATE_EGRESS", "0") == "1"
	cfg.RealityProbeAddr = getenv("REALITY_PROBE_ADDR", defaultRealityAddr)
	if cfg.RealityProfiles, err = parseRealityProfiles(os.Getenv("REALITY_INBOUNDS")); err != nil {
		return envConfig{}, err
	}
	cfg.BlockSMTP = getenv("WORKER_BLOCK_SMTP", "1") == "1"
	cfg.BlockBitTorrent = getenv("WORKER_BLOCK_BITTORRENT", "1") == "1"
	ackInterval, err := time.ParseDuration(getenv("ORCH_ACK_INTERVAL", "90s"))
	if err != nil || ackInterval < 10*time.Second || ackInterval > time.Hour {
		return envConfig{}, errors.New("ORCH_ACK_INTERVAL must be a duration between 10s and 1h")
	}
	cfg.OrchAckInterval = ackInterval
	if cfg.MetricsScrubPeerLabels {
		salt, err := loadMetricsScrubSalt(cfg.StateDir, os.Getenv("TW_METRICS_SCRUB_SALT"))
		if err != nil {
			return envConfig{}, fmt.Errorf("load metrics scrub salt: %w", err)
		}
		cfg.MetricsScrubSalt = salt
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
	profiles, err := parseAWGInboundProfiles(os.Getenv("AWG_INBOUNDS"), cfg)
	if err != nil {
		return envConfig{}, err
	}
	cfg.AWGProfiles = profiles
	if err := validateCamouflageDomain(cfg.CamouflageDomain); err != nil {
		return envConfig{}, err
	}
	cfg.RealityDest = realityDest(cfg.RealityDest, cfg.CamouflageDomain)
	if isSelfStealDest(cfg.RealityDest) {
		log.Printf("warning: REALITY_DEST=%s is the internal self-signed fallback; active probes can tell it apart from a real %s", cfg.RealityDest, cfg.CamouflageDomain)
	}
	return cfg, nil
}

func parseAWGInboundProfiles(raw string, cfg envConfig) ([]awgInboundProfile, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []awgInboundProfile{defaultAWGInboundProfile(cfg)}, nil
	}
	var profiles []awgInboundProfile
	if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
		return nil, fmt.Errorf("parse AWG_INBOUNDS: %w", err)
	}
	if len(profiles) == 0 {
		return nil, errors.New("AWG_INBOUNDS must contain at least one profile")
	}
	seen := map[string]struct{}{}
	seenInterfaces := map[string]string{}
	seenListenPorts := map[int]string{}
	seenUAPISockets := map[string]string{}
	seenSubnets := map[string]string{}
	hasBase := false
	for i := range profiles {
		if profiles[i].Name == "" && i == 0 {
			profiles[i].Name = "awg"
		}
		profiles[i].Name = normalizeAWGProfileName(profiles[i].Name)
		if profiles[i].Name == "" {
			return nil, fmt.Errorf("AWG_INBOUNDS[%d].name must be set", i)
		}
		if _, ok := seen[profiles[i].Name]; ok {
			return nil, fmt.Errorf("AWG_INBOUNDS profile %q is duplicated", profiles[i].Name)
		}
		seen[profiles[i].Name] = struct{}{}
		if profiles[i].Name == "awg" {
			hasBase = true
		}
		if profiles[i].Interface = strings.TrimSpace(profiles[i].Interface); profiles[i].Interface == "" {
			return nil, fmt.Errorf("AWG_INBOUNDS[%d].interface must be set", i)
		}
		if strings.ContainsAny(profiles[i].Interface, " \t\r\n/") || len(profiles[i].Interface) > 15 {
			return nil, fmt.Errorf("AWG_INBOUNDS[%d].interface is invalid", i)
		}
		if profiles[i].ListenPort < 1025 || profiles[i].ListenPort > 65535 {
			return nil, fmt.Errorf("AWG_INBOUNDS[%d].listen_port must be in 1025..65535", i)
		}
		if profiles[i].PublicPort == 0 {
			profiles[i].PublicPort = profiles[i].ListenPort
		}
		if profiles[i].PublicPort < 1 || profiles[i].PublicPort > 65535 {
			return nil, fmt.Errorf("AWG_INBOUNDS[%d].public_port must be in 1..65535", i)
		}
		profiles[i].Subnet = strings.TrimSpace(profiles[i].Subnet)
		prefix, err := netip.ParsePrefix(profiles[i].Subnet)
		if err != nil {
			return nil, fmt.Errorf("AWG_INBOUNDS[%d].subnet: %w", i, err)
		}
		profiles[i].Subnet = prefix.Masked().String()
		if profiles[i].Gateway == "" {
			gateway, err := firstHost(profiles[i].Subnet)
			if err != nil {
				return nil, fmt.Errorf("AWG_INBOUNDS[%d].subnet: %w", i, err)
			}
			profiles[i].Gateway = gateway
		}
		profiles[i].Gateway = strings.TrimSpace(profiles[i].Gateway)
		if profiles[i].UAPISocket == "" {
			profiles[i].UAPISocket = filepath.Join("/var/run/wireguard", profiles[i].Interface+".sock")
		}
		profiles[i].UAPISocket = filepath.Clean(strings.TrimSpace(profiles[i].UAPISocket))
		if err := rejectAWGProfileConflict(seenInterfaces, profiles[i].Interface, profiles[i].Name, "interface"); err != nil {
			return nil, err
		}
		if owner, ok := seenListenPorts[profiles[i].ListenPort]; ok {
			return nil, fmt.Errorf("AWG_INBOUNDS profiles %q and %q share listen_port %d", owner, profiles[i].Name, profiles[i].ListenPort)
		}
		seenListenPorts[profiles[i].ListenPort] = profiles[i].Name
		if err := rejectAWGProfileConflict(seenUAPISockets, profiles[i].UAPISocket, profiles[i].Name, "uapi_socket"); err != nil {
			return nil, err
		}
		if err := rejectAWGProfileConflict(seenSubnets, profiles[i].Subnet, profiles[i].Name, "subnet"); err != nil {
			return nil, err
		}
	}
	if !hasBase {
		return nil, errors.New("AWG_INBOUNDS must include base profile named awg")
	}
	return profiles, nil
}

func rejectAWGProfileConflict(seen map[string]string, value, profileName, field string) error {
	if owner, ok := seen[value]; ok {
		return fmt.Errorf("AWG_INBOUNDS profiles %q and %q share %s %q", owner, profileName, field, value)
	}
	seen[value] = profileName
	return nil
}

func defaultAWGInboundProfile(cfg envConfig) awgInboundProfile {
	return awgInboundProfile{
		Name:       "awg",
		Interface:  "awg1",
		ListenPort: awgInPort,
		PublicPort: cfg.AWGPort,
		Subnet:     cfg.AWGSubnet,
		Gateway:    cfg.AWGGateway,
		UAPISocket: cfg.AWGUAPISocket,
	}
}

func awgProfiles(cfg envConfig) []awgInboundProfile {
	if len(cfg.AWGProfiles) > 0 {
		return cfg.AWGProfiles
	}
	return []awgInboundProfile{defaultAWGInboundProfile(cfg)}
}

func baseAWGProfile(cfg envConfig) awgInboundProfile {
	for _, profile := range awgProfiles(cfg) {
		if profile.isBase() {
			return profile
		}
	}
	return awgProfiles(cfg)[0]
}

func normalizeAWGProfileName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		default:
			return ""
		}
	}
	return b.String()
}

func (p awgInboundProfile) isBase() bool {
	return p.Name == "" || p.Name == "awg"
}

func (p awgInboundProfile) registryPath(stateDir string) string {
	if p.isBase() {
		return filepath.Join(stateDir, "awg", "peers.json")
	}
	return filepath.Join(stateDir, "awg", "profiles", p.Name, "peers.json")
}

func (p awgInboundProfile) configPath(stateDir string) string {
	if p.isBase() {
		return filepath.Join(stateDir, "awg", "awg-gw.json")
	}
	return filepath.Join(stateDir, "awg", "profiles", p.Name, "awg-gw.json")
}

func validateCamouflageDomain(domain string) error {
	switch strings.ToLower(strings.TrimSpace(domain)) {
	case "", "example.com", "example.org":
		return errors.New("refusing placeholder CAMOUFLAGE_DOMAIN; set a real TLS1.3 domain")
	default:
		return nil
	}
}

// realityDest defaults to the camouflage domain itself, so a REALITY probe
// without a valid client key is answered by the real site with its real
// certificate.
func realityDest(configured, camouflageDomain string) string {
	if dest := strings.TrimSpace(configured); dest != "" {
		return dest
	}
	return net.JoinHostPort(strings.TrimSpace(camouflageDomain), "443")
}

func isSelfStealDest(dest string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(dest))
	return err == nil && port == strconv.Itoa(distributorTLS) && (host == "awg-gw" || host == "distributor")
}

func realityNetwork(cfg envConfig) string {
	switch strings.ToLower(strings.TrimSpace(cfg.XrayNetwork)) {
	case "xhttp":
		return "xhttp"
	default:
		return "tcp"
	}
}

func xhttpSettings(cfg envConfig) map[string]any {
	if realityNetwork(cfg) != "xhttp" {
		return nil
	}
	settings := map[string]any{
		"path": strings.TrimSpace(cfg.XHTTPPath),
		"mode": strings.TrimSpace(cfg.XHTTPMode),
	}
	if host := xhttpHost(cfg); host != "" {
		settings["host"] = host
	}
	extraRaw := strings.TrimSpace(cfg.XHTTPExtraJSON)
	if extraRaw != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(extraRaw), &extra); err != nil {
			log.Printf("invalid XRAY_XHTTP_EXTRA_JSON ignored: %v", err)
		} else {
			settings["extra"] = extra
		}
	}
	return settings
}

func xhttpHost(cfg envConfig) string {
	if host := strings.TrimSpace(cfg.XHTTPHost); host != "" {
		return host
	}
	return strings.TrimSpace(cfg.CamouflageDomain)
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
		if ensureRealityCohorts(&st) {
			if err := writeJSONFile(path, st, 0o600); err != nil {
				return stateFile{}, err
			}
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
	ensureRealityCohorts(&st)
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return stateFile{}, err
	}
	if err := createFileExclusive(path, append(raw, '\n'), 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			return bootstrap(cfg)
		}
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
	return applyXrayConfig(cfg, xrayRaw, len(devices))
}

func xrayConfigDocument(cfg envConfig, st stateFile, devices []approvedDevice) map[string]any {
	type realityClient struct {
		id, email, flow string
	}
	clients := []realityClient{}
	seen := map[string]struct{}{}
	seenEmails := map[string]struct{}{}
	if !cfg.DisableSmokePeers {
		clients = append(clients, realityClient{id: st.SmokeRealityUUID, email: "p0-smoke"})
		seen[st.SmokeRealityUUID] = struct{}{}
		seenEmails["p0-smoke"] = struct{}{}
	}
	for _, device := range devices {
		if device.Status != "approved" || device.RealityUUID == "" {
			continue
		}
		if _, ok := seen[device.RealityUUID]; ok {
			continue
		}
		// Emails identify users for live add/remove and per-user stats, so
		// they must be unique within the inbound.
		email := device.DeviceID
		if email == "" {
			email = "device-" + device.RealityUUID
		}
		if _, ok := seenEmails[email]; ok {
			log.Printf("approved device %s skipped for REALITY: duplicate device_id", sanitizeLogValue(email))
			continue
		}
		seen[device.RealityUUID] = struct{}{}
		seenEmails[email] = struct{}{}
		clients = append(clients, realityClient{id: device.RealityUUID, email: email, flow: device.RealityFlow})
	}
	shortIDs := realityShortIDs(st, revokedShortIDs(cfg.StateDir))
	inbounds := []any{}
	for _, profile := range realityProfiles(cfg) {
		profileClients := make([]any, 0, len(clients))
		for _, client := range clients {
			entry := map[string]any{"id": client.id, "email": client.email, "level": 0}
			// Vision is per device: the server rejects a client whose flow
			// differs from its account, so the orchestrator enables it only
			// for clients that support it. XHTTP does not carry XTLS.
			if client.flow != "" && profile.supportsVision() {
				entry["flow"] = client.flow
			}
			profileClients = append(profileClients, entry)
		}
		streamSettings := map[string]any{
			"network":  profile.Network,
			"security": "reality",
			"realitySettings": map[string]any{
				"show":        false,
				"dest":        cfg.RealityDest,
				"xver":        0,
				"serverNames": []string{cfg.CamouflageDomain},
				"privateKey":  st.Reality.PrivateKey,
				"shortIds":    shortIDs,
			},
		}
		if profile.Network == "xhttp" {
			settings := realityXHTTPSettings(profile)
			if profile.Name == realityBaseProfileName {
				settings = xhttpSettings(cfg)
			}
			streamSettings["xhttpSettings"] = settings
		}
		inbound := map[string]any{
			"tag":      profile.tag(),
			"listen":   "0.0.0.0",
			"port":     profile.ListenPort,
			"protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    profileClients,
			},
			"streamSettings": streamSettings,
		}
		if cfg.BlockBitTorrent {
			// Protocol-based routing needs sniffing; routeOnly keeps the
			// client's requested destination untouched.
			inbound["sniffing"] = map[string]any{
				"enabled":      true,
				"destOverride": []string{"http", "tls", "quic"},
				"routeOnly":    true,
			}
		}
		inbounds = append(inbounds, inbound)
	}
	apiInbound := map[string]any{
		"tag":      "api",
		"listen":   "127.0.0.1",
		"port":     xrayAPIInPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1"},
	}
	xcfg := map[string]any{
		"log":      map[string]any{"loglevel": "info"},
		"inbounds": append(inbounds, apiInbound),
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"api": map[string]any{
			"tag":      "api",
			"services": []string{"HandlerService", "StatsService"},
		},
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
		},
		"routing": xrayRouting(cfg),
		"stats":   map[string]any{},
	}
	return xcfg
}

// privateEgressCIDRs are destinations that clients must not reach through the
// worker: the Docker network with the agent and distributor, the host, cloud
// metadata services and other non-public ranges.
var privateEgressCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

func xrayRouting(cfg envConfig) map[string]any {
	rules := []any{map[string]any{
		"type":        "field",
		"inboundTag":  []string{"api"},
		"outboundTag": "api",
	}}
	// Abuse from a worker IP (spam, torrent DMCA notices) gets the host
	// suspended, so these are blocked by default.
	if cfg.BlockBitTorrent {
		rules = append(rules, map[string]any{
			"type":        "field",
			"protocol":    []string{"bittorrent"},
			"outboundTag": "block",
		})
	}
	if cfg.BlockSMTP {
		rules = append(rules, map[string]any{
			"type":        "field",
			"port":        "25,465,587",
			"outboundTag": "block",
		})
	}
	if cfg.AllowPrivateEgress {
		return map[string]any{"rules": rules}
	}
	rules = append(rules,
		map[string]any{
			"type":        "field",
			"domain":      []string{"regexp:^[^.]*$", "domain:localhost", "domain:local", "domain:internal"},
			"outboundTag": "block",
		},
		map[string]any{
			"type":        "field",
			"ip":          privateEgressCIDRs,
			"outboundTag": "block",
		},
	)
	// IPIfNonMatch resolves domains before the IP rule, so a public name that
	// points at a private address is blocked as well.
	return map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules}
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
	devices, cachedErr := loadCachedApprovedDevices(cfg.StateDir)
	skipRegistryWrite := false
	if cachedErr != nil {
		if orchAppliedSeq(cfg.StateDir) > 0 {
			log.Printf("awg registry render skipped by anti-wipe guard: %v", cachedErr)
			skipRegistryWrite = true
		}
		devices = nil
	} else {
		devices = filterUnexpiredApprovedDevices(devices, time.Now().UTC())
		if orchAppliedSeq(cfg.StateDir) > 0 && len(devices) == 0 {
			log.Printf("awg registry render skipped by anti-wipe guard: applied worker config has no approved devices")
			skipRegistryWrite = true
		}
	}
	for _, profile := range awgProfiles(cfg) {
		addr := profile.Gateway + "/" + prefixLen(profile.Subnet)
		awgCfg := map[string]any{
			"interface":        profile.Interface,
			"address":          addr,
			"listen_port":      profile.ListenPort,
			"private_key_hex":  st.AWG.PrivateKeyHex,
			"public_key":       st.AWG.PublicKey,
			"dialect":          st.Dialect,
			"peer_registry":    profile.registryPath(cfg.StateDir),
			"server_keepalive": cfg.AWGServerKeepalive,
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
	log.Printf("distributor certificate issued for %s", cfg.CamouflageDomain)
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
				log.Printf("distributor certificate renewal failed: %v", err)
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

func selfDescribe(cfg envConfig, st stateFile) map[string]any {
	reality := map[string]any{
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
		"network":     realityNetwork(cfg),
		"fingerprint": "chrome",
		"spiderX":     "/",
	}
	if xhttp := xhttpSettings(cfg); xhttp != nil {
		reality["xhttp"] = xhttp
	}
	cohorts := activeCohortShortIDs(st, revokedShortIDs(cfg.StateDir))
	reality["cohort_short_ids"] = cohorts
	realityProfilePayloads := []any{}
	for _, profile := range realityProfiles(cfg) {
		payload := map[string]any{
			"name":        profile.Name,
			"address":     cfg.PublicAddress,
			"port":        profile.PublicPort,
			"network":     profile.Network,
			"server_name": cfg.CamouflageDomain,
			"public_key":  st.Reality.PublicKey,
			"short_id":    st.Reality.ShortID,
			"flows":       []string{""},
		}
		if profile.supportsVision() {
			payload["flows"] = []string{"", flowVision}
		}
		if profile.Network == "xhttp" {
			payload["xhttp"] = realityXHTTPSettings(profile)
		}
		realityProfilePayloads = append(realityProfilePayloads, payload)
	}
	awgProfilePayloads := make([]any, 0, len(awgProfiles(cfg)))
	for _, profile := range awgProfiles(cfg) {
		awgProfilePayloads = append(awgProfilePayloads, awgSelfDescribe(cfg, st, profile))
	}
	baseAWG := awgSelfDescribe(cfg, st, baseAWGProfile(cfg))
	out := map[string]any{
		"schema":           "trafficwrapper-worker-p0",
		"hostname":         st.Hostname,
		"egress_ip":        cfg.EgressIP,
		"orch_url":         cfg.OrchURL,
		"agent_url":        cfg.WorkerAgentURL,
		"distributor_url":  cfg.DistributorURL,
		"standalone":       cfg.OrchURL == "",
		"dialect_id":       st.DialectID,
		"capacity":         cfg.Capacity,
		"protocols":        []string{"REALITY", "AWG"},
		"reality":          reality,
		"reality_profiles": realityProfilePayloads,
		"awg":              baseAWG,
		"awg_profiles":     awgProfilePayloads,
		"health":           healthSnapshot(),
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

func awgSelfDescribe(cfg envConfig, st stateFile, profile awgInboundProfile) map[string]any {
	return map[string]any{
		"profile":           profile.Name,
		"name":              profile.Name,
		"address":           cfg.PublicAddress,
		"endpoint":          net.JoinHostPort(cfg.PublicAddress, strconv.Itoa(profile.PublicPort)),
		"public_key":        st.AWG.PublicKey,
		"server_public":     st.AWG.PublicKey,
		"server_public_key": st.AWG.PublicKey,
		"port":              profile.PublicPort,
		"listen_port":       profile.ListenPort,
		"interface":         profile.Interface,
		"subnet":            profile.Subnet,
		"gateway":           profile.Gateway,
		"min_version_code":  profile.MinVersionCode,
		"dialect":           st.Dialect,
		"dialect_id":        st.DialectID,
		"smoke_peer_config": "/worker-state/smoke/awg-peer.conf",
	}
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

var egressEchoURLs = []string{"https://api.ipify.org", "https://ifconfig.co/ip", "https://ipinfo.io/ip"}

// detectPublicEgressIP asks several echo services in parallel and only trusts
// an address reported by at least two of them, like install.sh does. A lone
// answer is used only when every other service failed.
func detectPublicEgressIP() string {
	answers := make(chan string, len(egressEchoURLs))
	for _, url := range egressEchoURLs {
		url := url
		go func() {
			answers <- fetchEchoIP(url)
		}()
	}
	counts := map[string]int{}
	responded := 0
	lone := ""
	for range egressEchoURLs {
		ip := <-answers
		if ip == "" {
			continue
		}
		responded++
		lone = ip
		counts[ip]++
		if counts[ip] >= 2 {
			return ip
		}
	}
	if responded == 1 {
		log.Printf("egress IP %s confirmed by a single echo service only", lone)
		return lone
	}
	if responded > 1 {
		log.Printf("egress IP echo services disagree: %v", counts)
	}
	return ""
}

func fetchEchoIP(url string) string {
	client := http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		return ""
	}
	ip := strings.TrimSpace(string(raw))
	if !isPublicIP(ip) {
		return ""
	}
	return ip
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

func getenvIntInRange(key string, fallback, minValue, maxValue int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	if parsed < minValue || parsed > maxValue {
		return 0, fmt.Errorf("%s must be in %d..%d, got %d", key, minValue, maxValue, parsed)
	}
	return parsed, nil
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
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := writeSyncClose(f, raw, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

// createFileExclusive atomically publishes raw at path only if path does not
// exist yet, so concurrent bootstraps cannot overwrite each other's keys.
func createFileExclusive(path string, raw []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := writeSyncClose(f, raw, mode); err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return err
		}
		// Some bind-mounted filesystems do not support hard links; O_EXCL still
		// guarantees a single winner, only without an atomic content swap.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		if err := writeSyncClose(f, raw, mode); err != nil {
			_ = os.Remove(path)
			return err
		}
	}
	return syncDir(dir)
}

func writeSyncClose(f *os.File, raw []byte, mode os.FileMode) error {
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fatal(err error) {
	log.Printf("worker-agent: %v", err)
	os.Exit(1)
}
