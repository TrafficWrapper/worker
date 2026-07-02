package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	awgPeerKeepaliveSec = 25
	xrayRestartDebounce = 2 * time.Second
)

type approvedDevice struct {
	DeviceID     string `json:"device_id"`
	RealityUUID  string `json:"reality_uuid"`
	AWGPublicKey string `json:"awg_public_key"`
	InternalIP   string `json:"internal_ip"`
	PSK2         string `json:"psk2"`
	Status       string `json:"status"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	Limits       struct {
		ExpiresAt *string `json:"expires_at,omitempty"`
	} `json:"limits,omitempty"`
}

type workerConfigDocument struct {
	DesiredState struct {
		ApprovedDevices []approvedDevice `json:"approved_devices"`
	} `json:"desired_state"`
}

type awgPeerRegistry struct {
	Clients []awgPeerRegistryClient `json:"clients"`
}

type awgPeerRegistryClient struct {
	WGPublicKey string    `json:"wg_public_key"`
	InternalIP  string    `json:"internal_ip"`
	PSK2        string    `json:"psk2"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type awgDesiredPeer struct {
	PublicKey string
	PSK2      string
	AllowedIP string
}

type awgPeerConfig struct {
	PublicKeyHex      string
	AllowedIPs        []string
	Endpoint          string
	RxBytes           uint64
	TxBytes           uint64
	LastHandshakeSec  int64
	LastHandshakeNSec int64
}

func materializeApprovedDevices(cfg envConfig, st stateFile, workerConfigJSON string) error {
	devices, err := approvedDevicesFromWorkerConfig(workerConfigJSON)
	if err != nil {
		return err
	}
	devices = filterUnexpiredApprovedDevices(devices, time.Now().UTC())
	xrayRaw, err := xrayConfigBytes(cfg, st, devices)
	if err != nil {
		return fmt.Errorf("render xray config: %w", err)
	}
	if err := applyXrayConfigWithRestart(cfg, xrayRaw, len(devices), xrayRestartDebounce); err != nil {
		return err
	}
	desiredPeers, err := writeAWGPeerRegistry(cfg, st, devices)
	if err != nil {
		return fmt.Errorf("write awg peer registry: %w", err)
	}
	if cfg.AWGUAPISocket != "" {
		if err := syncAWGUAPI(cfg.AWGUAPISocket, desiredPeers); err != nil {
			return fmt.Errorf("sync awg uapi: %w", err)
		}
		log.Printf("awg materialized peers=%d via %s", len(desiredPeers), cfg.AWGUAPISocket)
	}
	return nil
}

func applyXrayConfigWithRestart(cfg envConfig, xrayRaw []byte, approvedDeviceCount int, debounce time.Duration) error {
	xrayChanged := xrayConfigChanged(cfg, xrayRaw)
	xrayNeedsRestart := xrayChanged || xrayRestartPending(cfg)
	if xrayNeedsRestart && cfg.XrayContainer == "" {
		return errors.New("xray config changed but XRAY_CONTAINER_NAME is not configured")
	}
	if xrayChanged {
		if err := markXrayRestartPending(cfg); err != nil {
			return fmt.Errorf("mark xray restart pending: %w", err)
		}
		if err := writeXrayConfigBytes(cfg, xrayRaw); err != nil {
			return fmt.Errorf("write xray config: %w", err)
		}
	}
	if xrayNeedsRestart {
		if debounce > 0 {
			log.Printf("xray restart pending; debouncing for %s", debounce)
			time.Sleep(debounce)
		}
		log.Printf("xray config changed; restarting container %s via %s", cfg.XrayContainer, cfg.DockerSocket)
		if err := restartDockerContainer(cfg.DockerSocket, cfg.XrayContainer); err != nil {
			return fmt.Errorf("restart xray container %s: %w", cfg.XrayContainer, err)
		}
		if err := clearXrayRestartPending(cfg); err != nil {
			return fmt.Errorf("clear xray restart pending: %w", err)
		}
		log.Printf("xray materialized approved_devices=%d and restarted %s", approvedDeviceCount, cfg.XrayContainer)
	}
	return nil
}

func approvedDevicesFromWorkerConfig(raw string) ([]approvedDevice, error) {
	var doc workerConfigDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, err
	}
	out := make([]approvedDevice, 0, len(doc.DesiredState.ApprovedDevices))
	for _, device := range doc.DesiredState.ApprovedDevices {
		if device.Status != "approved" {
			continue
		}
		if strings.TrimSpace(device.RealityUUID) == "" ||
			strings.TrimSpace(device.AWGPublicKey) == "" ||
			strings.TrimSpace(device.InternalIP) == "" ||
			strings.TrimSpace(device.PSK2) == "" {
			return nil, fmt.Errorf("approved device %q is incomplete", device.DeviceID)
		}
		out = append(out, device)
	}
	return out, nil
}

func cachedApprovedDevices(stateDir string) []approvedDevice {
	raw, err := os.ReadFile(filepath.Join(stateDir, "orch", "worker-config.json"))
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	devices, err := approvedDevicesFromWorkerConfig(string(raw))
	if err != nil {
		log.Printf("cached approved_devices ignored: %v", err)
		return nil
	}
	return devices
}

func filterUnexpiredApprovedDevices(devices []approvedDevice, now time.Time) []approvedDevice {
	out := make([]approvedDevice, 0, len(devices))
	for _, device := range devices {
		if expiresAt, ok := approvedDeviceExpiry(device); ok && !now.Before(expiresAt) {
			log.Printf("approved device %s expired at %s; skipping materialization", device.DeviceID, expiresAt.Format(time.RFC3339))
			continue
		}
		out = append(out, device)
	}
	return out
}

func writeAWGPeerRegistry(cfg envConfig, st stateFile, devices []approvedDevice) ([]awgDesiredPeer, error) {
	now := time.Now().UTC()
	expires := time.Now().UTC().Add(3650 * 24 * time.Hour)
	clients := []awgPeerRegistryClient{{
		WGPublicKey: st.AWG.SmokePublic,
		InternalIP:  st.AWG.SmokeIP,
		PSK2:        st.AWG.SmokePSK,
		ExpiresAt:   expires,
	}}
	desired := []awgDesiredPeer{{
		PublicKey: st.AWG.SmokePublic,
		PSK2:      st.AWG.SmokePSK,
		AllowedIP: st.AWG.SmokeIP,
	}}
	seen := map[string]struct{}{st.AWG.SmokePublic: {}}
	for _, device := range devices {
		if _, ok := seen[device.AWGPublicKey]; ok {
			continue
		}
		deviceExpires := expires
		if parsed, ok := approvedDeviceExpiry(device); ok {
			if !now.Before(parsed) {
				log.Printf("approved device %s expired at %s; skipping AWG peer", device.DeviceID, parsed.Format(time.RFC3339))
				continue
			}
			deviceExpires = parsed
		}
		seen[device.AWGPublicKey] = struct{}{}
		clients = append(clients, awgPeerRegistryClient{
			WGPublicKey: device.AWGPublicKey,
			InternalIP:  device.InternalIP,
			PSK2:        device.PSK2,
			ExpiresAt:   deviceExpires,
		})
		desired = append(desired, awgDesiredPeer{
			PublicKey: device.AWGPublicKey,
			PSK2:      device.PSK2,
			AllowedIP: device.InternalIP,
		})
	}
	if err := writeJSONFile(filepath.Join(cfg.StateDir, "awg", "peers.json"), awgPeerRegistry{Clients: clients}, 0o600); err != nil {
		return nil, err
	}
	return desired, nil
}

func approvedDeviceExpiry(device approvedDevice) (time.Time, bool) {
	value := strings.TrimSpace(device.ExpiresAt)
	if value == "" && device.Limits.ExpiresAt != nil {
		value = strings.TrimSpace(*device.Limits.ExpiresAt)
	}
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		log.Printf("approved device %s has invalid expires_at %q: %v", device.DeviceID, value, err)
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func syncAWGUAPI(socketPath string, desired []awgDesiredPeer) error {
	current, err := listAWGPeerConfigs(socketPath)
	if err != nil {
		return err
	}
	desiredHex := make(map[string]struct{}, len(desired))
	for _, peer := range desired {
		hexKey, err := base64KeyToHex(peer.PublicKey)
		if err != nil {
			return fmt.Errorf("desired peer public key: %w", err)
		}
		desiredHex[hexKey] = struct{}{}
		if err := addAWGPeer(socketPath, peer); err != nil {
			return err
		}
	}
	for _, peer := range current {
		if _, ok := desiredHex[peer.PublicKeyHex]; ok {
			continue
		}
		if err := removeAWGPeerHex(socketPath, peer.PublicKeyHex); err != nil {
			return err
		}
	}
	return nil
}

func addAWGPeer(socketPath string, peer awgDesiredPeer) error {
	pubHex, err := base64KeyToHex(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("wg public key: %w", err)
	}
	pskHex, err := base64KeyToHex(peer.PSK2)
	if err != nil {
		return fmt.Errorf("psk2: %w", err)
	}
	return writeUAPI(socketPath, []string{
		"set=1",
		"public_key=" + pubHex,
		"preshared_key=" + pskHex,
		fmt.Sprintf("persistent_keepalive_interval=%d", awgPeerKeepaliveSec),
		"replace_allowed_ips=true",
		"allowed_ip=" + peer.AllowedIP,
		"",
		"",
	})
}

func removeAWGPeerHex(socketPath, pubHex string) error {
	normalized, err := normalizeHexKey(pubHex)
	if err != nil {
		return err
	}
	return writeUAPI(socketPath, []string{
		"set=1",
		"public_key=" + normalized,
		"remove=true",
		"",
		"",
	})
}

func listAWGPeerConfigs(socketPath string) ([]awgPeerConfig, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial UAPI %s: %w", socketPath, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, "get=1\n\n"); err != nil {
		return nil, fmt.Errorf("write UAPI: %w", err)
	}
	peers := []awgPeerConfig{}
	current := -1
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "errno=0" {
			return peers, nil
		}
		if strings.HasPrefix(line, "errno=") {
			return nil, fmt.Errorf("UAPI returned %s", line)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			normalized, err := normalizeHexKey(value)
			if err != nil {
				return nil, err
			}
			peers = append(peers, awgPeerConfig{PublicKeyHex: normalized})
			current = len(peers) - 1
		case "allowed_ip":
			if current >= 0 {
				peers[current].AllowedIPs = append(peers[current].AllowedIPs, value)
			}
		case "endpoint":
			if current >= 0 {
				peers[current].Endpoint = value
			}
		case "rx_bytes":
			if current >= 0 {
				peers[current].RxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "tx_bytes":
			if current >= 0 {
				peers[current].TxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "last_handshake_time_sec":
			if current >= 0 {
				peers[current].LastHandshakeSec, _ = strconv.ParseInt(value, 10, 64)
			}
		case "last_handshake_time_nsec":
			if current >= 0 {
				peers[current].LastHandshakeNSec, _ = strconv.ParseInt(value, 10, 64)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("UAPI get response missing errno=0")
}

func writeUAPI(socketPath string, lines []string) error {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial UAPI %s: %w", socketPath, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, strings.Join(lines, "\n")); err != nil {
		return fmt.Errorf("write UAPI: %w", err)
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read UAPI response: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "errno=0" {
			return nil
		}
		if strings.HasPrefix(line, "errno=") {
			return fmt.Errorf("UAPI returned %s", line)
		}
	}
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

func normalizeHexKey(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	raw, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return value, nil
}

func restartDockerContainer(socketPath, name string) error {
	if name == "" {
		return nil
	}
	if _, err := os.Stat(socketPath); err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socketPath)
			},
		},
	}
	names := dockerContainerNameCandidates(name)
	for _, candidate := range names {
		restarted, err := restartDockerContainerByName(client, candidate)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errDockerContainerNotFound) {
			return err
		}
		if restarted {
			return nil
		}
	}
	discovered, err := discoverDockerContainerByComposeService(client, "xray")
	if err != nil {
		return fmt.Errorf("discover xray container: %w", err)
	}
	if discovered != "" {
		if _, err := restartDockerContainerByName(client, discovered); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("docker container %q not found; tried %s", name, strings.Join(names, ", "))
}

var errDockerContainerNotFound = errors.New("docker container not found")

func dockerContainerNameCandidates(name string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	add(name)
	add(strings.ReplaceAll(name, "_", "-"))
	add(strings.ReplaceAll(name, "-", "_"))
	if strings.Contains(name, "xray") {
		add("worker-xray-1")
		add("worker_xray_1")
	}
	return out
}

func restartDockerContainerByName(client *http.Client, name string) (bool, error) {
	endpoint := "http://docker/containers/" + url.PathEscape(name) + "/restart?t=5"
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, errDockerContainerNotFound
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("docker restart %s http %d: %s", name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	log.Printf("docker restarted container %s", name)
	return true, nil
}

func discoverDockerContainerByComposeService(client *http.Client, service string) (string, error) {
	filter := fmt.Sprintf(`{"label":["com.docker.compose.service=%s"]}`, service)
	endpoint := "http://docker/containers/json?all=true&filters=" + url.QueryEscape(filter)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("docker containers http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var containers []struct {
		ID     string   `json:"Id"`
		Names  []string `json:"Names"`
		State  string   `json:"State"`
		Status string   `json:"Status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&containers); err != nil {
		return "", err
	}
	for _, container := range containers {
		for _, name := range container.Names {
			name = strings.TrimPrefix(strings.TrimSpace(name), "/")
			if name != "" {
				return name, nil
			}
		}
		if container.ID != "" {
			return container.ID, nil
		}
	}
	return "", nil
}
