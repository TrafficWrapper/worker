package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/flynn/noise"

	"github.com/TrafficWrapper/worker/core/awg/device"
	awgdialect "github.com/TrafficWrapper/worker/core/awg/dialect"
)

const (
	prologue     = "TrafficWrapper provisioning v1"
	keySize      = 32
	maxFrameSize = 1 << 20
	defaultMTU   = 1420
	defaultTun   = "twprobe0"
	defaultAWGIP = "10.13.13.1"
	defaultCurl  = "https://api.ipify.org"
	defaultHold  = 3 * time.Second
)

type keyPairFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type dialect = awgdialect.Dialect

type provisionRequest struct {
	Username    string `json:"username"`
	Secret      string `json:"secret"`
	WGPublicKey string `json:"wg_public_key"`
}

type provisionResponse struct {
	OK              bool      `json:"ok"`
	Error           string    `json:"error,omitempty"`
	InternalIP      string    `json:"internal_ip,omitempty"`
	Endpoint        string    `json:"endpoint,omitempty"`
	ServerPublicKey string    `json:"server_public_key,omitempty"`
	PSK2            string    `json:"psk2,omitempty"`
	AWGPreset       dialect   `json:"awg_preset,omitempty"`
	TTL             int64     `json:"ttl,omitempty"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
}

type options struct {
	provisionAddr   string
	provisionPub    string
	identityKeyPath string
	username        string
	secret          string
	secretEnv       string
	secretFile      string
	tunName         string
	curlURL         string
	expectedIP      string
	serverTimeUnix  int64
	maxClockSkew    int64
	hold            time.Duration
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	opts := parseFlags()
	if err := checkClock(opts.serverTimeUnix, opts.maxClockSkew); err != nil {
		return err
	}
	secret, err := readSecret(opts.secret, opts.secretEnv, opts.secretFile)
	if err != nil {
		return err
	}
	identity, err := loadKeyPair(opts.identityKeyPath)
	if err != nil {
		return err
	}
	wgKey, err := noiseCipherSuite().GenerateKeypair(rand.Reader)
	if err != nil {
		return err
	}
	wgPublic := keyToBase64(wgKey.Public)

	resp, err := provision(opts, identity, wgPublic, secret)
	if err != nil {
		return err
	}
	if err := validateProvisionResponse(resp); err != nil {
		return err
	}
	fmt.Printf("provision_ok=true internal_ip=%s endpoint=%s ttl=%d wg_public_key=%s wg_private_key_sent=false\n", resp.InternalIP, resp.Endpoint, resp.TTL, wgPublic)
	fmt.Printf("preset=jc=%d jmin=%d jmax=%d s1=%d s2=%d s3=%d s4=%d h1=%s h2=%s h3=%s h4=%s\n",
		resp.AWGPreset.Jc, resp.AWGPreset.Jmin, resp.AWGPreset.Jmax,
		resp.AWGPreset.S1, resp.AWGPreset.S2, resp.AWGPreset.S3, resp.AWGPreset.S4,
		resp.AWGPreset.H1, resp.AWGPreset.H2, resp.AWGPreset.H3, resp.AWGPreset.H4)

	tdev, err := tun.CreateTUN(opts.tunName, defaultMTU)
	if err != nil {
		return fmt.Errorf("create TUN %s: %w", opts.tunName, err)
	}
	defer tdev.Close()
	if realName, err := tdev.Name(); err == nil && realName != "" {
		opts.tunName = realName
	}

	logger := device.NewLogger(device.LogLevelError, "probe: ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	defer dev.Close()
	if err := configureDevice(dev, wgKey.Private, resp); err != nil {
		return err
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}
	if err := configureOSInterface(opts.tunName, resp.InternalIP, resp.Endpoint); err != nil {
		return err
	}

	if err := runCommand("ping", "-I", opts.tunName, "-c", "3", "-W", "3", defaultAWGIP); err != nil {
		return err
	}
	outboundIP, err := runOutput("curl", "--interface", opts.tunName, "--max-time", "15", "-s", opts.curlURL)
	if err != nil {
		return err
	}
	outboundIP = strings.TrimSpace(outboundIP)
	fmt.Printf("outbound_ip=%s\n", outboundIP)
	if opts.expectedIP != "" && outboundIP != opts.expectedIP {
		return fmt.Errorf("unexpected outbound ip: got %s want %s", outboundIP, opts.expectedIP)
	}

	time.Sleep(opts.hold)
	if err := printDeviceStats(dev); err != nil {
		return err
	}
	return nil
}

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.provisionAddr, "provision-addr", "", "provisioning TCP address")
	flag.StringVar(&opts.provisionPub, "provision-server-public", "", "pinned provisioning server public key")
	flag.StringVar(&opts.identityKeyPath, "identity-key", "", "client identity key JSON")
	flag.StringVar(&opts.username, "username", "", "provisioning username")
	flag.StringVar(&opts.secret, "secret", "", "secret value")
	flag.StringVar(&opts.secretEnv, "secret-env", "", "environment variable with secret")
	flag.StringVar(&opts.secretFile, "secret-file", "", "file containing secret")
	flag.StringVar(&opts.tunName, "tun", defaultTun, "TUN interface name")
	flag.StringVar(&opts.curlURL, "curl-url", defaultCurl, "URL used for outbound IP check")
	flag.StringVar(&opts.expectedIP, "expect-ip", "", "expected outbound IP")
	flag.Int64Var(&opts.serverTimeUnix, "server-time-unix", 0, "server unix time for clock skew check")
	flag.Int64Var(&opts.maxClockSkew, "max-clock-skew", 5, "maximum allowed clock skew in seconds")
	flag.DurationVar(&opts.hold, "hold", defaultHold, "time to keep tunnel up after checks")
	flag.Parse()
	return opts
}

func checkClock(serverUnix, maxSkew int64) error {
	now := time.Now().Unix()
	if serverUnix == 0 {
		fmt.Printf("clock_check=skipped local_unix=%d reason=server-time-unix-not-set\n", now)
		return nil
	}
	skew := now - serverUnix
	if skew < 0 {
		skew = -skew
	}
	fmt.Printf("clock_check=ok local_unix=%d server_unix=%d skew_seconds=%d\n", now, serverUnix, skew)
	if skew > maxSkew {
		return fmt.Errorf("clock skew too high: %d seconds > %d", skew, maxSkew)
	}
	return nil
}

func provision(opts options, identity noise.DHKey, wgPublic, secret string) (provisionResponse, error) {
	if opts.provisionPub == "" || opts.identityKeyPath == "" || opts.username == "" {
		return provisionResponse{}, errors.New("provision-server-public, identity-key and username are required")
	}
	serverPub, err := decodeKeyBase64(opts.provisionPub)
	if err != nil {
		return provisionResponse{}, fmt.Errorf("provision server public key: %w", err)
	}
	conn, err := net.DialTimeout("tcp", opts.provisionAddr, 10*time.Second)
	if err != nil {
		return provisionResponse{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return provisionResponse{}, err
	}
	sendCipher, recvCipher, err := noiseIK(conn, identity, serverPub)
	if err != nil {
		return provisionResponse{}, err
	}
	req := provisionRequest{Username: opts.username, Secret: secret, WGPublicKey: wgPublic}
	if err := writeEncryptedJSON(conn, sendCipher, req); err != nil {
		return provisionResponse{}, err
	}
	var resp provisionResponse
	if err := readEncryptedJSON(conn, recvCipher, &resp); err != nil {
		return provisionResponse{}, err
	}
	if !resp.OK {
		return provisionResponse{}, fmt.Errorf("provisioning rejected request: %s", resp.Error)
	}
	return resp, nil
}

func noiseIK(conn net.Conn, identity noise.DHKey, serverPub []byte) (*noise.CipherState, *noise.CipherState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseCipherSuite(),
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte(prologue),
		StaticKeypair: identity,
		PeerStatic:    serverPub,
	})
	if err != nil {
		return nil, nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(conn, msg1); err != nil {
		return nil, nil, err
	}
	msg2, err := readFrame(conn)
	if err != nil {
		return nil, nil, err
	}
	if _, sendCipher, recvCipher, err := hs.ReadMessage(nil, msg2); err != nil {
		return nil, nil, err
	} else {
		return sendCipher, recvCipher, nil
	}
}

func configureDevice(dev *device.Device, privateKey []byte, resp provisionResponse) error {
	privateHex, err := bytesToHexKey(privateKey)
	if err != nil {
		return err
	}
	serverHex, err := base64KeyToHex(resp.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("server public key: %w", err)
	}
	pskHex, err := base64KeyToHex(resp.PSK2)
	if err != nil {
		return fmt.Errorf("psk2: %w", err)
	}
	lines := []string{
		"private_key=" + privateHex,
		"replace_peers=true",
	}
	lines = append(lines, awgdialect.UAPILines(resp.AWGPreset)...)
	lines = append(lines,
		"public_key="+serverHex,
		"preshared_key="+pskHex,
		"endpoint="+resp.Endpoint,
		"persistent_keepalive_interval=15",
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"",
	)
	uapi := strings.Join(lines, "\n")
	if err := dev.IpcSetOperation(strings.NewReader(uapi)); err != nil {
		return fmt.Errorf("apply UAPI: %w", err)
	}
	return nil
}

func configureOSInterface(tunName, internalIP, endpoint string) error {
	localPrefix, err := clientInterfacePrefix(internalIP)
	if err != nil {
		return err
	}
	if err := runCommand("ip", "addr", "replace", localPrefix, "dev", tunName); err != nil {
		return err
	}
	if err := runCommand("ip", "link", "set", "dev", tunName, "mtu", strconv.Itoa(defaultMTU), "up"); err != nil {
		return err
	}
	route, err := defaultRoute()
	if err != nil {
		return err
	}
	endpointHost, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	if err := runCommand("ip", "route", "replace", endpointHost+"/32", "via", route.via, "dev", route.dev); err != nil {
		return err
	}
	if err := runCommand("ip", "route", "replace", "default", "dev", tunName); err != nil {
		return err
	}
	fmt.Printf("routes=endpoint:%s via %s dev %s default:%s\n", endpointHost, route.via, route.dev, tunName)
	return nil
}

type routeInfo struct {
	via string
	dev string
}

func defaultRoute() (routeInfo, error) {
	out, err := runOutput("ip", "route", "show", "default")
	if err != nil {
		return routeInfo{}, err
	}
	fields := strings.Fields(out)
	var route routeInfo
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			if i+1 < len(fields) {
				route.via = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				route.dev = fields[i+1]
			}
		}
	}
	if route.via == "" || route.dev == "" {
		return routeInfo{}, fmt.Errorf("could not parse default route: %s", strings.TrimSpace(out))
	}
	return route, nil
}

func clientInterfacePrefix(internalIP string) (string, error) {
	prefix, err := netip.ParsePrefix(internalIP)
	if err != nil {
		return "", err
	}
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("internal_ip must be IPv4, got %s", internalIP)
	}
	return prefix.Addr().String() + "/24", nil
}

func printDeviceStats(dev *device.Device) error {
	var b strings.Builder
	if err := dev.IpcGetOperation(&b); err != nil {
		return err
	}
	for _, line := range strings.Split(b.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "public_key="),
			strings.HasPrefix(line, "last_handshake_time_sec="),
			strings.HasPrefix(line, "tx_bytes="),
			strings.HasPrefix(line, "rx_bytes="),
			strings.HasPrefix(line, "endpoint="),
			strings.HasPrefix(line, "allowed_ip="):
			fmt.Println("probe_uapi_" + line)
		}
	}
	return nil
}

func validateProvisionResponse(resp provisionResponse) error {
	if resp.InternalIP == "" || resp.Endpoint == "" || resp.ServerPublicKey == "" || resp.PSK2 == "" {
		return errors.New("provisioning response is incomplete")
	}
	if err := validateDialect(resp.AWGPreset, defaultMTU); err != nil {
		return err
	}
	if _, err := decodeKeyBase64(resp.ServerPublicKey); err != nil {
		return fmt.Errorf("server_public_key: %w", err)
	}
	if _, err := decodeKeyBase64(resp.PSK2); err != nil {
		return fmt.Errorf("psk2: %w", err)
	}
	return nil
}

func validateDialect(d dialect, mtu int) error {
	return awgdialect.Validate(d, mtu)
}

func noiseCipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

func loadKeyPair(path string) (noise.DHKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return noise.DHKey{}, err
	}
	var file keyPairFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return noise.DHKey{}, err
	}
	privateBytes, err := decodeKeyBase64(file.PrivateKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("private key: %w", err)
	}
	publicBytes, err := decodeKeyBase64(file.PublicKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("public key: %w", err)
	}
	return noise.DHKey{Private: privateBytes, Public: publicBytes}, nil
}

func readSecret(value, envName, filePath string) (string, error) {
	switch {
	case value != "":
		return value, nil
	case envName != "":
		secret := os.Getenv(envName)
		if secret == "" {
			return "", fmt.Errorf("env %s is empty", envName)
		}
		return secret, nil
	case filePath != "":
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(raw), "\r\n"), nil
	default:
		return "", errors.New("secret must be provided by --secret, --secret-env or --secret-file")
	}
}

func writeEncryptedJSON(w io.Writer, cipher *noise.CipherState, value any) error {
	plain, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encrypted, err := cipher.Encrypt(nil, nil, plain)
	if err != nil {
		return err
	}
	return writeFrame(w, encrypted)
}

func readEncryptedJSON(r io.Reader, cipher *noise.CipherState, value any) error {
	encrypted, err := readFrame(r)
	if err != nil {
		return err
	}
	plain, err := cipher.Decrypt(nil, nil, encrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, value)
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d", size)
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func writeFull(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func decodeKeyBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(raw) != keySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", keySize, len(raw))
	}
	return raw, nil
}

func keyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func base64KeyToHex(value string) (string, error) {
	raw, err := decodeKeyBase64(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func bytesToHexKey(value []byte) (string, error) {
	if len(value) != keySize {
		return "", fmt.Errorf("expected %d bytes, got %d", keySize, len(value))
	}
	return hex.EncodeToString(value), nil
}

func runCommand(name string, args ...string) error {
	out, err := runCombined(name, args...)
	if strings.TrimSpace(out) != "" {
		fmt.Printf("%s_output:\n%s\n", name, strings.TrimSpace(out))
	}
	if err != nil {
		return fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func runOutput(name string, args ...string) (string, error) {
	out, err := runCombined(name, args...)
	if err != nil {
		return "", fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return out, nil
}

func runCombined(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), ctx.Err()
	}
	return string(out), err
}
