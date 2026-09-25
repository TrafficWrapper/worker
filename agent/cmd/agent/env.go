package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/serverpeer"
)

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
	XrayAPISocket          string
	XrayBinary             string
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
	PublicAddressV6        string
	DNSEnabled             bool
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
	AgentAPIAllowCIDRs     string
	// RealityMaxTimeDiff bounds how far a client's ClientHello time may be
	// from the worker's, so a recorded handshake cannot be replayed later.
	RealityMaxTimeDiff time.Duration
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
	// OwnDialect gives the profile its own generated dialect instead of the
	// worker's, so a dialect can be rotated by moving clients to a new profile.
	OwnDialect bool `json:"own_dialect,omitempty"`
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
		MetricsScrubPeerLabels: metricsScrubPeerLabels(),
		AgentAPIAllowCIDRs:     os.Getenv("AGENT_API_ALLOW_CIDRS"),
		XrayAPISocket:          getenv("XRAY_API_SOCKET", defaultXrayAPISocket),
		XrayBinary:             getenv("XRAY_BINARY", "/usr/local/bin/xray"),
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
	if cfg.AllowPrivateEgress, err = serverpeer.EnvBool("WORKER_ALLOW_PRIVATE_EGRESS", false); err != nil {
		return envConfig{}, err
	}
	cfg.RealityProbeAddr = getenv("REALITY_PROBE_ADDR", defaultRealityAddr)
	cfg.DNSEnabled = getenv("WORKER_DNS", "0") == "1"
	if cfg.PublicAddressV6, err = publicAddressV6(getenv("PUBLIC_ADDRESS_V6", "")); err != nil {
		return envConfig{}, err
	}
	if cfg.RealityProfiles, err = parseRealityProfiles(os.Getenv("REALITY_INBOUNDS")); err != nil {
		return envConfig{}, err
	}
	// awg-gw parses the same switches with the same parser, so REALITY and
	// AWG clients always get the same blocking.
	if cfg.BlockSMTP, err = serverpeer.EnvBool("WORKER_BLOCK_SMTP", true); err != nil {
		return envConfig{}, err
	}
	if cfg.BlockBitTorrent, err = serverpeer.EnvBool("WORKER_BLOCK_BITTORRENT", true); err != nil {
		return envConfig{}, err
	}
	ackInterval, err := time.ParseDuration(getenv("ORCH_ACK_INTERVAL", "90s"))
	if err != nil || ackInterval < 10*time.Second || ackInterval > time.Hour {
		return envConfig{}, errors.New("ORCH_ACK_INTERVAL must be a duration between 10s and 1h")
	}
	cfg.OrchAckInterval = ackInterval
	maxTimeDiff, err := getenvIntInRange("REALITY_MAX_TIME_DIFF", 120, 0, 3600)
	if err != nil {
		return envConfig{}, err
	}
	cfg.RealityMaxTimeDiff = time.Duration(maxTimeDiff) * time.Second
	if cfg.MetricsScrubPeerLabels {
		salt, err := loadMetricsScrubSalt(cfg.StateDir, os.Getenv("TW_METRICS_SCRUB_SALT"))
		if err != nil {
			// Labels stay scrubbed; they only change on every restart.
			slog.Warn("metrics scrub salt not persisted; using a per-process salt", "err", err)
			salt = randHex(32)
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
	if err := validateSelfDescribeEnv(cfg); err != nil {
		return envConfig{}, err
	}
	if isSelfStealDest(cfg.RealityDest) {
		slog.Warn("REALITY_DEST is the internal self-signed fallback; active probes can tell it apart from the real camouflage site", "reality_dest", cfg.RealityDest, "camouflage_domain", cfg.CamouflageDomain)
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
