package main

import (
	"context"
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
	"github.com/TrafficWrapper/worker/core/awg/serverpeer"
)

const (
	defaultInterface = "awg1"
	defaultAddress   = "10.13.13.1/24"
	defaultPort      = 51821
	defaultConfig    = "/worker-state/awg/awg-gw.json"
	defaultRegistry  = "/worker-state/provisioning/clients.json"
)

var version = "dev"

type Config = serverpeer.GatewayConfig

type Dialect = awgdialect.Dialect

type publicConfig struct {
	Interface       string  `json:"interface"`
	Address         string  `json:"address"`
	ListenPort      int     `json:"listen_port"`
	PublicKey       string  `json:"public_key"`
	Dialect         Dialect `json:"dialect"`
	Registry        string  `json:"peer_registry"`
	ServerKeepalive int     `json:"server_keepalive"`
}

type (
	registryFile   = serverpeer.Registry
	registryClient = serverpeer.RegistryClient
)

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
		err = runHealthcheck(args)
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
	if path, ok := configFlag(args); ok {
		return path
	}
	return defaultConfig
}

// configFlag returns the value of --config and whether it was given.
func configFlag(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// runCommand runs a host networking command (ip, nft, tc); tests replace it.
var runCommand = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// createTUN is tun.CreateTUN; tests replace it to check the startup order.
var createTUN = tun.CreateTUN

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

	logLevel, err := awgLogLevel(os.Getenv("AWG_LOG_LEVEL"))
	if err != nil {
		return err
	}
	logger := device.NewLogger(logLevel, fmt.Sprintf("(%s) ", cfg.Interface))
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

	// The isolation filter goes in before the interface exists, so no client
	// packet is ever forwarded without it; the rules match by name.
	isolation, err := isolationFromEnv()
	if err != nil {
		return err
	}
	workers, err := parseWorkerAddresses(cfg.WorkerAddresses)
	if err != nil {
		return err
	}
	if err := configureClientIsolation(cfg.Interface, isolation, workers); err != nil {
		return err
	}

	tdev, err := createTUN(cfg.Interface, effectiveMTU)
	if err != nil {
		return fmt.Errorf("create TUN %s: %w", cfg.Interface, err)
	}
	realName, err := tdev.Name()
	if err == nil && realName != "" && realName != cfg.Interface {
		cfg.Interface = realName
		if err := configureClientIsolation(cfg.Interface, isolation, workers); err != nil {
			tdev.Close()
			return err
		}
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

	go runRateLimits(ctx, cfg.Interface, cfg.PeerRegistry)

	fmt.Println("status=awg-gw running; UAPI socket ready")
	select {
	case <-ctx.Done():
		fmt.Println("awg-gw shutting down")
		return nil
	case err := <-errs:
		return err
	case <-dev.Wait():
		return nil
	}
}

// awgLogLevel defaults to errors only: verbose logging prints every handshake
// and keepalive of every peer, which is heavy on busy gateways.
func awgLogLevel(value string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "error":
		return device.LogLevelError, nil
	case "verbose", "debug":
		return device.LogLevelVerbose, nil
	case "silent":
		return device.LogLevelSilent, nil
	default:
		return 0, fmt.Errorf("AWG_LOG_LEVEL must be verbose, error or silent, got %q", value)
	}
}

// serveUAPI accepts UAPI connections until the listener is closed. A failed
// Accept (for example running out of file descriptors) is retried with a
// short backoff instead of stopping the gateway and every tunnel with it.
func serveUAPI(dev uapiHandler, uapi net.Listener, errs chan<- error) {
	delay := uapiAcceptMinDelay
	for {
		c, err := uapi.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				errs <- err
				return
			}
			fmt.Fprintf(os.Stderr, "uapi accept failed, retrying in %s: %v\n", delay, err)
			time.Sleep(delay)
			delay = min(delay*2, uapiAcceptMaxDelay)
			continue
		}
		delay = uapiAcceptMinDelay
		go dev.IpcHandle(c)
	}
}

// uapiHandler is the part of *device.Device serveUAPI needs.
type uapiHandler interface {
	IpcHandle(net.Conn)
}

var (
	uapiAcceptMinDelay = 50 * time.Millisecond
	uapiAcceptMaxDelay = 5 * time.Second
)

func applyDeviceConfig(dev *device.Device, cfg Config) error {
	peers, err := loadActivePeers(cfg.PeerRegistry, time.Now().UTC())
	if err != nil {
		return err
	}
	uapiConfig := strings.Join(deviceConfigLines(cfg, peers), "\n")
	if err := dev.IpcSetOperation(strings.NewReader(uapiConfig)); err != nil {
		return fmt.Errorf("apply UAPI config: %w", err)
	}
	fmt.Printf("restored_peers=%d\n", len(peers))
	return nil
}

func deviceConfigLines(cfg Config, peers []restoredPeer) []string {
	lines := []string{
		"private_key=" + cfg.PrivateKeyHex,
		"listen_port=" + strconv.Itoa(cfg.ListenPort),
		"replace_peers=true",
	}
	lines = append(lines, awgdialect.UAPILines(cfg.Dialect)...)
	for _, peer := range peers {
		lines = append(lines, serverpeer.PeerUAPILines(peer.PublicKeyHex, peer.PSKHex, peer.AllowedIP, cfg.ServerKeepalive)...)
	}
	lines = append(lines, "")
	return lines
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
		fmt.Fprintf(os.Stderr, "warning: peer registry %s is empty; starting without peers until the agent reconciles\n", path)
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
		peer, err := restoredPeerFromClient(client)
		if err != nil {
			// A single malformed entry must not keep the whole gateway down.
			fmt.Fprintf(os.Stderr, "warning: registry client %d skipped: %v\n", i, err)
			continue
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

func restoredPeerFromClient(client registryClient) (restoredPeer, error) {
	publicHex, err := serverpeer.KeyB64ToHex(client.WGPublicKey)
	if err != nil {
		return restoredPeer{}, fmt.Errorf("wg_public_key: %w", err)
	}
	pskHex, err := serverpeer.KeyB64ToHex(client.PSK2)
	if err != nil {
		return restoredPeer{}, fmt.Errorf("psk2: %w", err)
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(client.InternalIP))
	if err != nil {
		return restoredPeer{}, fmt.Errorf("internal_ip: %w", err)
	}
	if prefix.Bits() != prefix.Addr().BitLen() {
		return restoredPeer{}, fmt.Errorf("internal_ip %s is not a single host", prefix)
	}
	client.InternalIP = prefix.String()
	return restoredPeer{PublicKeyHex: publicHex, PSKHex: pskHex, AllowedIP: client.InternalIP}, nil
}

func configureInterface(name, address string, mtu int) error {
	commands := [][]string{
		{"ip", "address", "replace", address, "dev", name},
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"},
	}
	for _, args := range commands {
		out, err := runCommand(args[0], args[1:]...)
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
	table := natTableName(name)
	commands := [][]string{
		{"nft", "add", "table", "ip", table},
		{"nft", "add", "chain", "ip", table, "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "policy", "accept", ";", "}"},
		{"nft", "flush", "chain", "ip", table, "postrouting"},
		{"nft", "add", "rule", "ip", table, "postrouting", "oifname", "!=", name, "ip", "saddr", prefix.String(), "masquerade"},
	}
	for _, args := range commands {
		out, err := runCommand(args[0], args[1:]...)
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

// privateDestinations are never forwarded for tunnel clients: the Docker
// network with the agent and distributor, the host, other clients, cloud
// metadata services and other non-public ranges.
var privateDestinations = []string{
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
}

var privateDestinations6 = []string{
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// isolationSettings are the client egress switches. They are parsed with the
// same strict parser as the agent's, so AWG and REALITY clients get the same
// blocking for any value.
type isolationSettings struct {
	BlockPrivate bool
	BlockSMTP    bool
}

func isolationFromEnv() (isolationSettings, error) {
	allowPrivate, err := serverpeer.EnvBool("WORKER_ALLOW_PRIVATE_EGRESS", false)
	if err != nil {
		return isolationSettings{}, err
	}
	blockSMTP, err := serverpeer.EnvBool("WORKER_BLOCK_SMTP", true)
	if err != nil {
		return isolationSettings{}, err
	}
	return isolationSettings{BlockPrivate: !allowPrivate, BlockSMTP: blockSMTP}, nil
}

// configureClientIsolation fails when a required rule cannot be installed, so
// the gateway never serves clients without the filter.
func configureClientIsolation(name string, settings isolationSettings, workers []netip.Addr) error {
	allowPrivate, blockSMTP := !settings.BlockPrivate, settings.BlockSMTP
	if allowPrivate && !blockSMTP {
		fmt.Println("client_isolation=disabled by WORKER_ALLOW_PRIVATE_EGRESS=1")
		return nil
	}
	commands := clientIsolationCommands(name, !allowPrivate, blockSMTP)
	if !allowPrivate {
		commands = append(commands, workerAddressCommands(name, workers)...)
	}
	for _, args := range commands {
		out, err := runCommand(args[0], args[1:]...)
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if strings.Contains(msg, "File exists") {
				continue
			}
			return fmt.Errorf("%s failed: %w: %s", strings.Join(args, " "), err, msg)
		}
	}
	fmt.Printf("client_isolation=enabled iface=%s private=%t smtp=%t worker_addresses=%d\n", name, !allowPrivate, blockSMTP, len(workers))
	return nil
}

// workerAddressCommands drop client traffic to the worker's own public
// addresses: through them clients would reach services published on the
// host, which the private ranges do not cover. Must follow
// clientIsolationCommands, which creates the chain.
func workerAddressCommands(name string, workers []netip.Addr) [][]string {
	table := natTableName(name) + "_isolation"
	var v4, v6 []string
	for _, addr := range workers {
		if addr.Is4() {
			v4 = append(v4, addr.String())
		} else {
			v6 = append(v6, addr.String())
		}
	}
	var commands [][]string
	if len(v4) > 0 {
		commands = append(commands, []string{"nft", "add", "rule", "inet", table, "forward", "iifname", name, "ip", "daddr", "{", strings.Join(v4, ", "), "}", "drop"})
	}
	if len(v6) > 0 {
		commands = append(commands, []string{"nft", "add", "rule", "inet", table, "forward", "iifname", name, "ip6", "daddr", "{", strings.Join(v6, ", "), "}", "drop"})
	}
	return commands
}

// parseWorkerAddresses accepts only literal IPs without a zone; the agent
// never writes anything else, so any other value is a config error.
func parseWorkerAddresses(values []string) ([]netip.Addr, error) {
	addrs := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Zone() != "" {
			return nil, fmt.Errorf("worker_addresses: %q is not an IP address", value)
		}
		addrs = append(addrs, addr.Unmap())
	}
	return addrs, nil
}

func clientIsolationCommands(name string, blockPrivate, blockSMTP bool) [][]string {
	table := natTableName(name) + "_isolation"
	commands := [][]string{
		{"nft", "add", "table", "inet", table},
		{"nft", "add", "chain", "inet", table, "forward", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "accept", ";", "}"},
		{"nft", "flush", "chain", "inet", table, "forward"},
	}
	if blockPrivate {
		commands = append(commands,
			[]string{"nft", "add", "rule", "inet", table, "forward", "iifname", name, "ip", "daddr", "{", strings.Join(privateDestinations, ", "), "}", "drop"},
			[]string{"nft", "add", "rule", "inet", table, "forward", "iifname", name, "ip6", "daddr", "{", strings.Join(privateDestinations6, ", "), "}", "drop"},
		)
	}
	if blockSMTP {
		// Outbound mail from a worker IP gets the host blacklisted.
		commands = append(commands, []string{"nft", "add", "rule", "inet", table, "forward", "iifname", name, "tcp", "dport", "{", "25, 465, 587", "}", "drop"})
	}
	return commands
}

func natTableName(iface string) string {
	if iface == defaultInterface {
		return "trafficwrapper_awg"
	}
	var b strings.Builder
	for _, r := range iface {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "trafficwrapper_awg_custom"
	}
	return "trafficwrapper_awg_" + b.String()
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

// runHealthcheck checks the interface of the config given with --config, the
// same flag "run" takes, so a gateway started with another config is not
// reported by the state of the base interface. Without the flag a missing
// default config means stub mode; a config named explicitly must exist.
func runHealthcheck(args []string) error {
	path, explicit := configFlag(args)
	if !explicit {
		path = defaultConfig
	}
	if _, err := os.Stat(path); err != nil {
		if explicit {
			return fmt.Errorf("healthcheck config: %w", err)
		}
		fmt.Println("awg-gw stub healthy")
		return nil
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if out, err := runCommand("ip", "link", "show", "dev", cfg.Interface); err != nil {
		return fmt.Errorf("healthcheck ip link: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Printf("awg-gw run mode healthy interface=%s\n", cfg.Interface)
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
		Interface:       cfg.Interface,
		Address:         cfg.Address,
		ListenPort:      cfg.ListenPort,
		PublicKey:       cfg.PublicKey,
		Dialect:         cfg.Dialect,
		Registry:        cfg.PeerRegistry,
		ServerKeepalive: cfg.ServerKeepalive,
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
	serverKeepalive, err := serverKeepaliveFromEnv(cfg.ServerKeepalive)
	if err != nil {
		return Config{}, err
	}
	cfg.ServerKeepalive = serverKeepalive
	return cfg, nil
}

func validateConfig(cfg Config) error {
	if err := validateInterfaceName(cfg.Interface); err != nil {
		return err
	}
	if _, err := netip.ParsePrefix(cfg.Address); err != nil {
		return fmt.Errorf("invalid address prefix: %w", err)
	}
	if cfg.ListenPort < 1025 || cfg.ListenPort > 65535 {
		return fmt.Errorf("listen_port must be in 1025..65535, got %d", cfg.ListenPort)
	}
	if cfg.ServerKeepalive < 0 || cfg.ServerKeepalive > 65535 {
		return fmt.Errorf("server_keepalive must be in 0..65535, got %d", cfg.ServerKeepalive)
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
	if _, err := parseWorkerAddresses(cfg.WorkerAddresses); err != nil {
		return err
	}
	if err := awgdialect.Validate(cfg.Dialect, device.DefaultMTU); err != nil {
		return err
	}
	_, err := awgdialect.EffectiveMTU(device.DefaultMTU, cfg.Dialect)
	return err
}

func validateInterfaceName(name string) error {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return errors.New("interface must be set")
	case len(name) > 15:
		return fmt.Errorf("interface must be 15 chars or less, got %d", len(name))
	case strings.ContainsAny(name, " \t\r\n/"):
		return fmt.Errorf("interface must not contain whitespace or slash: %q", name)
	default:
		return nil
	}
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

func serverKeepaliveFromEnv(fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv("AWG_SERVER_KEEPALIVE"))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("AWG_SERVER_KEEPALIVE must be an integer: %w", err)
	}
	if parsed < 0 || parsed > 65535 {
		return 0, fmt.Errorf("AWG_SERVER_KEEPALIVE must be in 0..65535, got %d", parsed)
	}
	return parsed, nil
}
