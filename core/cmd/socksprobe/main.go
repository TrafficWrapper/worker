package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	awgdialect "github.com/TrafficWrapper/worker/core/awg/dialect"
	"github.com/TrafficWrapper/worker/core/internal/provisionclient"
	"github.com/TrafficWrapper/worker/core/transport"
)

const (
	defaultProvisionAddr = ""
	defaultCurlURL       = "https://api.ipify.org"
)

type options struct {
	provisionAddr     string
	provisionPub      string
	identityKeyPath   string
	username          string
	secret            string
	secretEnv         string
	secretFile        string
	socksListen       string
	curlURL           string
	expectedIP        string
	throughputURL     string
	throughputRepeat  int
	throughputMaxTime time.Duration
	configOut         string
	configIn          string
	hold              time.Duration
}

type startResult struct {
	OK     bool         `json:"ok"`
	Error  string       `json:"error,omitempty"`
	Status *probeStatus `json:"status,omitempty"`
}

type probeStatus struct {
	SOCKSListen string `json:"socks_listen,omitempty"`
}

type transportConfig struct {
	PrivateKey      string          `json:"private_key"`
	InternalIP      string          `json:"internal_ip"`
	Endpoint        string          `json:"endpoint"`
	ServerPublicKey string          `json:"server_public_key"`
	PSK2            string          `json:"psk2"`
	AWGPreset       transportPreset `json:"awg_preset"`
	SOCKSListen     string          `json:"socks_listen,omitempty"`
	MTU             int             `json:"mtu,omitempty"`
}

type transportPreset = awgdialect.Dialect

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "socksprobe: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	opts := parseFlags()
	printRuntimeConstraints()
	if err := printIPLinks("ip_link_before"); err != nil {
		return err
	}

	configJSON, err := buildTransportConfig(opts)
	if err != nil {
		return err
	}
	if opts.configOut != "" {
		if err := os.WriteFile(opts.configOut, configJSON, 0o600); err != nil {
			return err
		}
		fmt.Printf("config_written=%s\n", opts.configOut)
	}
	startJSON := transport.Start(string(configJSON))
	fmt.Printf("start_result=%s\n", startJSON)
	defer func() {
		fmt.Printf("stop_result=%s\n", transport.Stop())
	}()

	start, err := parseStartResult(startJSON)
	if err != nil {
		return err
	}
	socksAddr := opts.socksListen
	if start.Status != nil && start.Status.SOCKSListen != "" {
		socksAddr = start.Status.SOCKSListen
	}
	fmt.Printf("stat_before=%s\n", transport.Stat())
	outboundIP, err := runCurlThroughSOCKS(socksAddr, opts.curlURL)
	if err != nil {
		return err
	}
	fmt.Printf("curl_socks5_ip=%s\n", outboundIP)
	if opts.expectedIP != "" && outboundIP != opts.expectedIP {
		return fmt.Errorf("unexpected outbound ip: got %s want %s", outboundIP, opts.expectedIP)
	}
	for i := 0; i < opts.throughputRepeat; i++ {
		if err := runThroughputCurl(socksAddr, opts.throughputURL, opts.throughputMaxTime, i+1); err != nil {
			return err
		}
	}
	time.Sleep(opts.hold)
	fmt.Printf("stat_after=%s\n", transport.Stat())
	if err := printIPLinks("ip_link_after"); err != nil {
		return err
	}
	return nil
}

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.provisionAddr, "provision-addr", defaultProvisionAddr, "provisioning TCP address")
	flag.StringVar(&opts.provisionPub, "provision-server-public", "", "pinned provisioning server public key")
	flag.StringVar(&opts.identityKeyPath, "identity-key", "", "client identity key JSON")
	flag.StringVar(&opts.username, "username", "", "provisioning username")
	flag.StringVar(&opts.secret, "secret", "", "secret value")
	flag.StringVar(&opts.secretEnv, "secret-env", "", "environment variable with secret")
	flag.StringVar(&opts.secretFile, "secret-file", "", "file containing secret")
	flag.StringVar(&opts.socksListen, "socks", "127.0.0.1:18080", "local SOCKS5 listen address")
	flag.StringVar(&opts.curlURL, "curl-url", defaultCurlURL, "URL used for outbound IP check")
	flag.StringVar(&opts.expectedIP, "expect-ip", "", "expected outbound IP")
	flag.StringVar(&opts.throughputURL, "throughput-url", "", "URL downloaded through SOCKS for throughput measurement")
	flag.IntVar(&opts.throughputRepeat, "throughput-repeat", 0, "number of throughput downloads to run")
	flag.DurationVar(&opts.throughputMaxTime, "throughput-max-time", 5*time.Minute, "maximum time for each throughput download")
	flag.StringVar(&opts.configOut, "write-config", "", "write transport config JSON to path")
	flag.StringVar(&opts.configIn, "config-in", "", "read transport config JSON and skip provisioning")
	flag.DurationVar(&opts.hold, "hold", 2*time.Second, "time to keep transport up after curl")
	flag.Parse()
	return opts
}

func buildTransportConfig(opts options) ([]byte, error) {
	if opts.configIn != "" {
		raw, err := os.ReadFile(opts.configIn)
		if err != nil {
			return nil, err
		}
		fmt.Printf("config_read=%s\n", opts.configIn)
		return raw, nil
	}
	privateKey, publicKey, err := provisionclient.GenerateWireGuardKeyPair()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	resp, err := provisionclient.Provision(ctx, provisionclient.Options{
		Addr:            opts.provisionAddr,
		ServerPublicKey: opts.provisionPub,
		IdentityKeyPath: opts.identityKeyPath,
		Username:        opts.username,
		Secret:          opts.secret,
		SecretEnv:       opts.secretEnv,
		SecretFile:      opts.secretFile,
	}, publicKey)
	if err != nil {
		return nil, err
	}
	fmt.Printf("provision_ok=true internal_ip=%s endpoint=%s ttl=%d wg_public_key=%s wg_private_key_sent=false\n",
		resp.InternalIP, resp.Endpoint, resp.TTL, publicKey)
	fmt.Printf("preset=jc=%d jmin=%d jmax=%d s1=%d s2=%d s3=%d s4=%d h1=%s h2=%s h3=%s h4=%s\n",
		resp.AWGPreset.Jc, resp.AWGPreset.Jmin, resp.AWGPreset.Jmax,
		resp.AWGPreset.S1, resp.AWGPreset.S2, resp.AWGPreset.S3, resp.AWGPreset.S4,
		resp.AWGPreset.H1, resp.AWGPreset.H2, resp.AWGPreset.H3, resp.AWGPreset.H4)
	cfg := transportConfig{
		PrivateKey:      privateKey,
		InternalIP:      resp.InternalIP,
		Endpoint:        resp.Endpoint,
		ServerPublicKey: resp.ServerPublicKey,
		PSK2:            resp.PSK2,
		AWGPreset:       transportPreset(resp.AWGPreset),
		SOCKSListen:     opts.socksListen,
		MTU:             1420,
	}
	return json.Marshal(cfg)
}

func parseStartResult(raw string) (startResult, error) {
	var result startResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return startResult{}, err
	}
	if !result.OK {
		if result.Error == "" {
			result.Error = "transport start failed"
		}
		return startResult{}, errors.New(result.Error)
	}
	return result, nil
}

func runCurlThroughSOCKS(socksAddr, url string) (string, error) {
	fmt.Printf("curl_command=curl --socks5 %s --max-time 25 -s %s\n", socksAddr, url)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "curl", "--socks5", socksAddr, "--max-time", "25", "-s", url)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("curl through socks failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func runThroughputCurl(socksAddr, url string, maxTime time.Duration, attempt int) error {
	if url == "" {
		return nil
	}
	seconds := int(maxTime.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	fmt.Printf("throughput_command=curl --socks5 %s --max-time %d --output /dev/null --write-out ... %s\n", socksAddr, seconds, url)
	ctx, cancel := context.WithTimeout(context.Background(), maxTime+10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx,
		"curl",
		"--socks5", socksAddr,
		"--max-time", strconv.Itoa(seconds),
		"--silent",
		"--show-error",
		"--output", "/dev/null",
		"--write-out", "http_code=%{http_code} size_download=%{size_download} speed_download=%{speed_download} time_total=%{time_total}",
		url,
	)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	line := strings.TrimSpace(string(out))
	fmt.Printf("throughput_result_%d=%s\n", attempt, line)
	if err != nil {
		return fmt.Errorf("throughput curl failed: %w: %s", err, line)
	}
	if !strings.Contains(line, "http_code=200") && !strings.Contains(line, "http_code=206") {
		return fmt.Errorf("throughput curl returned unexpected status: %s", line)
	}
	return nil
}

func printRuntimeConstraints() {
	devTun := pathExists("/dev/net/tun")
	capNetAdmin, capLine := hasCapNetAdmin()
	fmt.Printf("runtime_no_dev_net_tun=%t dev_net_tun_exists=%t\n", !devTun, devTun)
	fmt.Printf("runtime_no_cap_net_admin=%t cap_net_admin=%t %s\n", !capNetAdmin, capNetAdmin, capLine)
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func hasCapNetAdmin() (bool, string) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, "cap_eff_unreadable=true"
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return false, "cap_eff_parse_error=true"
			}
			value, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return false, "cap_eff_parse_error=true"
			}
			return value&(1<<12) != 0, "cap_eff=0x" + fields[1]
		}
	}
	return false, "cap_eff_missing=true"
}

func printIPLinks(label string) error {
	out, err := runOutput("ip", "-o", "link", "show")
	if err != nil {
		return err
	}
	fmt.Printf("%s:\n%s\n", label, strings.TrimSpace(out))
	fmt.Printf("%s_tun_or_wg_present=%t\n", label, hasTunOrWGInterface(out))
	return nil
}

func hasTunOrWGInterface(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		name = strings.Split(name, "@")[0]
		switch {
		case strings.HasPrefix(name, "tun"),
			strings.HasPrefix(name, "wg"),
			strings.Contains(name, "twprobe"):
			return true
		}
	}
	return false
}

func runOutput(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), ctx.Err()
	}
	if err != nil {
		return string(out), fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
