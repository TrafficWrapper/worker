package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/tun"

	"github.com/TrafficWrapper/worker/core/awg/device"
	"github.com/TrafficWrapper/worker/core/awg/dialect"
)

const (
	defaultStateDir = "/worker-state"
	defaultTun      = "twsmoke0"
	defaultMTU      = 1420
	defaultGateway  = "10.13.13.1"
	defaultTWURL    = "http://10.13.13.1:8080/tw/config.json"
)

type stateFile struct {
	AWG     awgState        `json:"awg"`
	Dialect dialect.Dialect `json:"dialect"`
}

type awgState struct {
	PublicKey    string `json:"public_key"`
	SmokePrivate string `json:"smoke_private_key"`
	SmokePSK     string `json:"smoke_psk"`
	SmokeIP      string `json:"smoke_ip"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "awg-smoke: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	stateDir := getenv("WORKER_STATE_DIR", defaultStateDir)
	endpoint := getenv("AWG_ENDPOINT", "host.docker.internal:51888")
	gateway := getenv("AWG_GATEWAY", defaultGateway)
	url := getenv("TW_SMOKE_URL", defaultTWURL)

	st, err := readState(filepath.Join(stateDir, "bootstrap.json"))
	if err != nil {
		return err
	}
	st.applyClientOverrides()
	effectiveMTU, err := dialect.EffectiveMTU(defaultMTU, st.Dialect)
	if err != nil {
		return err
	}
	tdev, err := tun.CreateTUN(defaultTun, effectiveMTU)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	defer tdev.Close()
	tunName := defaultTun
	if name, err := tdev.Name(); err == nil && name != "" {
		tunName = name
	}

	logger := device.NewLogger(device.LogLevelError, "awg-smoke: ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	defer dev.Close()
	if err := configureDevice(dev, st, endpoint); err != nil {
		return err
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}
	if err := configureInterface(tunName, st.AWG.SmokeIP, gateway, effectiveMTU); err != nil {
		return err
	}

	if err := waitHTTP(url, 20*time.Second); err != nil {
		return err
	}
	stats, err := deviceStats(dev)
	if err != nil {
		return err
	}
	fmt.Printf("awg_smoke_ok=true endpoint=%s gateway=%s tun=%s mtu=%d\n", endpoint, gateway, tunName, effectiveMTU)
	fmt.Print(stats)
	return nil
}

func readState(path string) (stateFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return stateFile{}, err
	}
	var st stateFile
	if err := json.Unmarshal(raw, &st); err != nil {
		return stateFile{}, err
	}
	if st.AWG.PublicKey == "" || st.AWG.SmokePrivate == "" || st.AWG.SmokePSK == "" || st.AWG.SmokeIP == "" {
		return stateFile{}, fmt.Errorf("bootstrap AWG smoke fields are incomplete")
	}
	if err := dialect.ValidateProduction(st.Dialect, defaultMTU); err != nil {
		return stateFile{}, err
	}
	return st, nil
}

func (st *stateFile) applyClientOverrides() {
	if value := strings.TrimSpace(os.Getenv("AWG_CLIENT_PRIVATE_KEY")); value != "" {
		st.AWG.SmokePrivate = value
	}
	if value := strings.TrimSpace(os.Getenv("AWG_CLIENT_PSK")); value != "" {
		st.AWG.SmokePSK = value
	}
	if value := strings.TrimSpace(os.Getenv("AWG_CLIENT_IP")); value != "" {
		st.AWG.SmokeIP = value
	}
}

func configureDevice(dev *device.Device, st stateFile, endpoint string) error {
	endpoint, err := normalizeEndpoint(endpoint)
	if err != nil {
		return err
	}
	privateHex, err := base64KeyToHex(st.AWG.SmokePrivate)
	if err != nil {
		return fmt.Errorf("smoke private key: %w", err)
	}
	serverHex, err := base64KeyToHex(st.AWG.PublicKey)
	if err != nil {
		return fmt.Errorf("server public key: %w", err)
	}
	pskHex, err := base64KeyToHex(st.AWG.SmokePSK)
	if err != nil {
		return fmt.Errorf("psk2: %w", err)
	}
	lines := []string{
		"private_key=" + privateHex,
		"replace_peers=true",
	}
	lines = append(lines, dialect.UAPILines(st.Dialect)...)
	lines = append(lines,
		"public_key="+serverHex,
		"preshared_key="+pskHex,
		"endpoint="+endpoint,
		"persistent_keepalive_interval=15",
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"",
	)
	if err := dev.IpcSetOperation(strings.NewReader(strings.Join(lines, "\n"))); err != nil {
		return fmt.Errorf("apply UAPI: %w", err)
	}
	return nil
}

func normalizeEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(addr.String(), port), nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("resolve endpoint host %q: %w", host, err)
	}
	for _, ip := range addrs {
		if ip4 := ip.To4(); ip4 != nil {
			return net.JoinHostPort(net.IP(ip4).String(), port), nil
		}
	}
	for _, ip := range addrs {
		if ip16 := ip.To16(); ip16 != nil {
			return net.JoinHostPort(net.IP(ip16).String(), port), nil
		}
	}
	return "", fmt.Errorf("resolve endpoint host %q: no usable addresses", host)
}

func configureInterface(name, smokeIP, gateway string, mtu int) error {
	prefix, err := smokeInterfacePrefix(smokeIP)
	if err != nil {
		return err
	}
	commands := [][]string{
		{"ip", "addr", "replace", prefix, "dev", name},
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"},
		{"ip", "route", "replace", gateway + "/32", "dev", name},
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

func waitHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2048))
			_ = resp.Body.Close()
			if readErr != nil {
				lastErr = readErr
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 && (strings.Contains(string(body), "trafficwrapper-worker-p0") || strings.Contains(string(body), "client-config-v1")) {
				return nil
			} else {
				lastErr = fmt.Errorf("unexpected %s body=%q", resp.Status, strings.TrimSpace(string(body)))
			}
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("GET %s through AWG failed: %w", url, lastErr)
}

func deviceStats(dev *device.Device) (string, error) {
	var b strings.Builder
	if err := dev.IpcGetOperation(&b); err != nil {
		return "", err
	}
	var out strings.Builder
	for _, line := range strings.Split(b.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "last_handshake_time_sec="),
			strings.HasPrefix(line, "last_handshake_time_nsec="),
			strings.HasPrefix(line, "tx_bytes="),
			strings.HasPrefix(line, "rx_bytes="),
			strings.HasPrefix(line, "endpoint="),
			strings.HasPrefix(line, "allowed_ip="):
			out.WriteString("awg_smoke_")
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.String(), nil
}

func smokeInterfacePrefix(smokeIP string) (string, error) {
	prefix, err := netip.ParsePrefix(smokeIP)
	if err != nil {
		return "", err
	}
	addr := prefix.Addr()
	if !addr.Is4() {
		return "", fmt.Errorf("smoke_ip must be IPv4")
	}
	return addr.String() + "/24", nil
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

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
