package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/tun"

	"github.com/TrafficWrapper/worker/core/awg/device"
	awgdialect "github.com/TrafficWrapper/worker/core/awg/dialect"
)

const (
	defaultInterface    = "awg1"
	defaultAddress      = "10.13.13.1/24"
	defaultPort         = 51821
	defaultConfig       = "/worker-state/awg/awg-gw.json"
	defaultRegistry     = "/worker-state/provisioning/clients.json"
	awgPeerKeepaliveSec = 25
)

var version = "dev"

type Config struct {
	Interface     string  `json:"interface"`
	Address       string  `json:"address"`
	ListenPort    int     `json:"listen_port"`
	PrivateKeyHex string  `json:"private_key_hex"`
	PublicKey     string  `json:"public_key"`
	Dialect       Dialect `json:"dialect"`
	PeerRegistry  string  `json:"peer_registry,omitempty"`
}

type Dialect = awgdialect.Dialect

type publicConfig struct {
	Interface  string  `json:"interface"`
	Address    string  `json:"address"`
	ListenPort int     `json:"listen_port"`
	PublicKey  string  `json:"public_key"`
	Dialect    Dialect `json:"dialect"`
	Registry   string  `json:"peer_registry"`
}

type registryFile struct {
	Clients []registryClient `json:"clients"`
}

type registryClient struct {
	WGPublicKey string    `json:"wg_public_key"`
	InternalIP  string    `json:"internal_ip"`
	PSK2        string    `json:"psk2"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type restoredPeer struct {
	PublicKeyHex string
	PSKHex       string
	AllowedIP    string
}

func main() {
	cmd := "stub"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}

	var err error
	switch cmd {
	case "stub":
		err = runStub()
	case "run":
		err = runGateway(configPath(args))
	case "healthcheck":
		err = runHealthcheck()
	case "validate-config":
		err = validateConfigCommand(configPath(args))
	case "show-config":
		err = showConfigCommand(configPath(args))
	case "--version", "version":
		fmt.Printf("trafficwrapper awg-gw version=%s\n", version)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "awg-gw: %v\n", err)
		os.Exit(1)
	}
}

func configPath(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return defaultConfig
}

func runStub() error {
	serviceName := getenv("SERVICE_NAME", "awg-gw")
	listenUDP := getenv("AWG_LISTEN_UDP", strconv.Itoa(defaultPort))
	subnet := getenv("AWG_SUBNET", "10.13.13.0/24")

	fmt.Printf("TrafficWrapper %s version=%s\n", serviceName, version)
	fmt.Printf("purpose=AmneziaWG gateway stub; future %s UDP/%s subnet=%s\n", defaultInterface, listenUDP, subnet)
	fmt.Println("core_device_import=github.com/TrafficWrapper/worker/core/awg/device")
	fmt.Println("status=stub loop started; no TUN, no NET_ADMIN, no host ports in stub mode")

	return waitLoop(serviceName)
}

func runGateway(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	logger := device.NewLogger(device.LogLevelVerbose, fmt.Sprintf("(%s) ", cfg.Interface))
	fmt.Printf("TrafficWrapper awg-gw version=%s\n", version)
	fmt.Printf("mode=run interface=%s address=%s listen_port=%d\n", cfg.Interface, cfg.Address, cfg.ListenPort)
	fmt.Printf("public_key=%s\n", cfg.PublicKey)
	fmt.Printf("dialect=%s\n", dialectSummary(cfg.Dialect))
	fmt.Printf("peer_registry=%s\n", cfg.PeerRegistry)

	effectiveMTU, err := awgdialect.EffectiveMTU(device.DefaultMTU, cfg.Dialect)
	if err != nil {
		return err
	}
	fmt.Printf("mtu_base=%d mtu_effective=%d tcp_mss=%d transport_padding_s4=%d mobile_safe_outer_mtu=%d\n",
		device.DefaultMTU,
		effectiveMTU,
		awgdialect.TCPMSSForMTU(effectiveMTU),
		cfg.Dialect.S4,
		awgdialect.MobileSafeOuterMTU,
	)

	tdev, err := tun.CreateTUN(cfg.Interface, effectiveMTU)
	if err != nil {
		return fmt.Errorf("create TUN %s: %w", cfg.Interface, err)
	}
	realName, err := tdev.Name()
	if err == nil && realName != "" {
		cfg.Interface = realName
	}

	uapiFile, err := ipc.UAPIOpen(cfg.Interface)
	if err != nil {
		tdev.Close()
		return fmt.Errorf("open UAPI socket: %w", err)
	}

	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	defer dev.Close()

	if err := applyDeviceConfig(dev, cfg); err != nil {
		uapiFile.Close()
		return err
	}
	if err := dev.Up(); err != nil {
		uapiFile.Close()
		return fmt.Errorf("bring device up: %w", err)
	}
	if err := configureInterface(cfg.Interface, cfg.Address, effectiveMTU); err != nil {
		uapiFile.Close()
		return err
	}
	if err := configureEgressNAT(cfg.Interface, cfg.Address); err != nil {
		uapiFile.Close()
		return err
	}

	uapi, err := ipc.UAPIListen(cfg.Interface, uapiFile)
	if err != nil {
		uapiFile.Close()
		return fmt.Errorf("listen on UAPI socket: %w", err)
	}
	defer uapi.Close()

	errs := make(chan error, 1)
	go serveUAPI(dev, uapi, errs)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	fmt.Println("status=awg-gw running; UAPI socket ready")
	for {
		select {
		case <-ctx.Done():
			fmt.Println("awg-gw shutting down")
			return nil
		case err := <-errs:
			return err
		case <-dev.Wait():
			return nil
		case now := <-ticker.C:
			fmt.Printf("awg-gw alive ts=%s\n", now.UTC().Format(time.RFC3339))
		}
	}
}

func serveUAPI(dev *device.Device, uapi net.Listener, errs chan<- error) {
	for {
		c, err := uapi.Accept()
		if err != nil {
			errs <- err
			return
		}
		go dev.IpcHandle(c)
	}
}

func applyDeviceConfig(dev *device.Device, cfg Config) error {
	peers, err := loadActivePeers(cfg.PeerRegistry, time.Now().UTC())
	if err != nil {
		return err
	}
	lines := []string{
		"private_key=" + cfg.PrivateKeyHex,
		"listen_port=" + strconv.Itoa(cfg.ListenPort),
		"replace_peers=true",
	}
	lines = append(lines, awgdialect.UAPILines(cfg.Dialect)...)
	for _, peer := range peers {
		lines = append(lines,
			"public_key="+peer.PublicKeyHex,
			"preshared_key="+peer.PSKHex,
			fmt.Sprintf("persistent_keepalive_interval=%d", awgPeerKeepaliveSec),
			"replace_allowed_ips=true",
			"allowed_ip="+peer.AllowedIP,
		)
	}
	lines = append(lines, "")
	uapiConfig := strings.Join(lines, "\n")
	if err := dev.IpcSetOperation(strings.NewReader(uapiConfig)); err != nil {
		return fmt.Errorf("apply UAPI config: %w", err)
	}
	fmt.Printf("restored_peers=%d\n", len(peers))
	return nil
}

func loadActivePeers(path string, now time.Time) ([]restoredPeer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read peer registry %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var registry registryFile
	if err := json.Unmarshal(raw, &registry); err != nil {
		return nil, fmt.Errorf("parse peer registry %s: %w", path, err)
	}
	peers := make([]restoredPeer, 0, len(registry.Clients))
	for i, client := range registry.Clients {
		if !client.ExpiresAt.IsZero() && !client.ExpiresAt.After(now) {
			continue
		}
		peer, err := client.restoredPeer()
		if err != nil {
			return nil, fmt.Errorf("registry client %d: %w", i, err)
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

func (client registryClient) restoredPeer() (restoredPeer, error) {
	publicHex, err := base64KeyToHex(client.WGPublicKey)
	if err != nil {
		return restoredPeer{}, fmt.Errorf("wg_public_key: %w", err)
	}
	pskHex, err := base64KeyToHex(client.PSK2)
	if err != nil {
		return restoredPeer{}, fmt.Errorf("psk2: %w", err)
	}
	if _, err := netip.ParsePrefix(client.InternalIP); err != nil {
		return restoredPeer{}, fmt.Errorf("internal_ip: %w", err)
	}
	return restoredPeer{PublicKeyHex: publicHex, PSKHex: pskHex, AllowedIP: client.InternalIP}, nil
}

func base64KeyToHex(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func configureInterface(name, address string, mtu int) error {
	commands := [][]string{
		{"ip", "address", "replace", address, "dev", name},
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"},
	}
	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func configureEgressNAT(name, address string) error {
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return fmt.Errorf("parse NAT prefix: %w", err)
	}
	prefix = prefix.Masked()
	if err := ensureIPv4Forwarding(); err != nil {
		return err
	}
	commands := [][]string{
		{"nft", "add", "table", "ip", "trafficwrapper_awg"},
		{"nft", "add", "chain", "ip", "trafficwrapper_awg", "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "policy", "accept", ";", "}"},
		{"nft", "flush", "chain", "ip", "trafficwrapper_awg", "postrouting"},
		{"nft", "add", "rule", "ip", "trafficwrapper_awg", "postrouting", "oifname", "!=", name, "ip", "saddr", prefix.String(), "masquerade"},
	}
	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if strings.Contains(msg, "File exists") || strings.Contains(msg, "Could not process rule: File exists") {
				continue
			}
			return fmt.Errorf("%s failed: %w: %s", strings.Join(args, " "), err, msg)
		}
	}
	fmt.Printf("nat=enabled subnet=%s exclude_if=%s\n", prefix.String(), name)
	return nil
}

func ensureIPv4Forwarding() error {
	const path = "/proc/sys/net/ipv4/ip_forward"
	if forwardingEnabled(path) {
		return nil
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		if forwardingEnabled(path) {
			return nil
		}
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	if !forwardingEnabled(path) {
		return fmt.Errorf("enable ip_forward: %s is not 1 after write", path)
	}
	return nil
}

func forwardingEnabled(path string) bool {
	raw, err := os.ReadFile(path)
	return err == nil && strings.TrimSpace(string(raw)) == "1"
}

func runHealthcheck() error {
	if _, err := os.Stat(defaultConfig); err == nil {
		cfg, err := loadConfig(defaultConfig)
		if err != nil {
			return err
		}
		cmd := exec.Command("ip", "link", "show", "dev", cfg.Interface)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("healthcheck ip link: %w: %s", err, strings.TrimSpace(string(out)))
		}
		fmt.Println("awg-gw run mode healthy")
		return nil
	}
	fmt.Println("awg-gw stub healthy")
	return nil
}

func validateConfigCommand(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("config valid: %s\n", publicSummary(cfg))
	return nil
}

func showConfigCommand(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(publicConfig{
		Interface:  cfg.Interface,
		Address:    cfg.Address,
		ListenPort: cfg.ListenPort,
		PublicKey:  cfg.PublicKey,
		Dialect:    cfg.Dialect,
		Registry:   cfg.PeerRegistry,
	})
}

func loadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.Interface == "" {
		cfg.Interface = defaultInterface
	}
	if cfg.Address == "" {
		cfg.Address = defaultAddress
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = defaultPort
	}
	if cfg.PeerRegistry == "" {
		cfg.PeerRegistry = defaultRegistry
	}
	return cfg, nil
}

func validateConfig(cfg Config) error {
	if cfg.Interface != defaultInterface {
		return fmt.Errorf("interface must be %s, got %s", defaultInterface, cfg.Interface)
	}
	if _, err := netip.ParsePrefix(cfg.Address); err != nil {
		return fmt.Errorf("invalid address prefix: %w", err)
	}
	if cfg.ListenPort != defaultPort {
		return fmt.Errorf("listen_port must be %d, got %d", defaultPort, cfg.ListenPort)
	}
	if len(cfg.PrivateKeyHex) != 64 {
		return fmt.Errorf("private_key_hex must be 64 hex chars")
	}
	if _, err := parseHex32(cfg.PrivateKeyHex); err != nil {
		return fmt.Errorf("private_key_hex invalid: %w", err)
	}
	if strings.TrimSpace(cfg.PublicKey) == "" {
		return errors.New("public_key must be set for reporting")
	}
	if err := awgdialect.Validate(cfg.Dialect, device.DefaultMTU); err != nil {
		return err
	}
	_, err := awgdialect.EffectiveMTU(device.DefaultMTU, cfg.Dialect)
	return err
}

func parseHex32(value string) ([32]byte, error) {
	var out [32]byte
	if len(value) != 64 {
		return out, fmt.Errorf("got %d chars", len(value))
	}
	for i := 0; i < 32; i++ {
		b, err := strconv.ParseUint(value[i*2:i*2+2], 16, 8)
		if err != nil {
			return out, err
		}
		out[i] = byte(b)
	}
	return out, nil
}

func dialectSummary(d Dialect) string {
	return awgdialect.Summary(d)
}

func publicSummary(cfg Config) string {
	return fmt.Sprintf(
		"interface=%s address=%s listen_port=%d public_key=%s %s",
		cfg.Interface, cfg.Address, cfg.ListenPort, cfg.PublicKey, dialectSummary(cfg.Dialect),
	)
}

func waitLoop(serviceName string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("%s shutting down\n", serviceName)
			return nil
		case now := <-ticker.C:
			fmt.Printf("%s alive ts=%s\n", serviceName, now.UTC().Format(time.RFC3339))
		}
	}
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
