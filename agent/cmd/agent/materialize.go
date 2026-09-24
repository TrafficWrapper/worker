package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/serverpeer"
)

// maxRateMbps bounds per-device AWG rate limits (0 means unlimited).
const maxRateMbps = 100000

var realityUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type approvedDevice struct {
	DeviceID     string                              `json:"device_id"`
	RealityUUID  string                              `json:"reality_uuid"`
	RealityFlow  string                              `json:"reality_flow,omitempty"`
	AWGPublicKey string                              `json:"awg_public_key"`
	InternalIP   string                              `json:"internal_ip"`
	PSK2         string                              `json:"psk2"`
	AWGProfiles  map[string]approvedDeviceAWGProfile `json:"awg_profiles,omitempty"`
	Status       string                              `json:"status"`
	ExpiresAt    string                              `json:"expires_at,omitempty"`
	Limits       struct {
		ExpiresAt    *string `json:"expires_at,omitempty"`
		DownloadMbps int     `json:"download_mbps,omitempty"`
		UploadMbps   int     `json:"upload_mbps,omitempty"`
	} `json:"limits,omitempty"`
}

type approvedDeviceAWGProfile struct {
	AWGPublicKey string `json:"awg_public_key"`
	InternalIP   string `json:"internal_ip"`
	PSK2         string `json:"psk2"`
}

type workerConfigDocument struct {
	DesiredState struct {
		ApprovedDevices []approvedDevice `json:"approved_devices"`
	} `json:"desired_state"`
}

type (
	awgPeerRegistry       = serverpeer.Registry
	awgPeerRegistryClient = serverpeer.RegistryClient
)

type awgDesiredPeer struct {
	PublicKey string
	PSK2      string
	AllowedIP string
}

type awgPeerConfig struct {
	PublicKeyHex        string
	PresharedKeyHex     string `json:"-"`
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive int64
	RxBytes             uint64
	TxBytes             uint64
	LastHandshakeSec    int64
	LastHandshakeNSec   int64
}

type awgProfilePeerSnapshot struct {
	Profile    string          `json:"profile"`
	Interface  string          `json:"interface"`
	UAPISocket string          `json:"uapi_socket"`
	Peers      []awgPeerConfig `json:"peers,omitempty"`
	Error      string          `json:"error,omitempty"`
}

func collectAWGProfilePeerSnapshots(cfg envConfig) []awgProfilePeerSnapshot {
	profiles := awgProfiles(cfg)
	out := make([]awgProfilePeerSnapshot, len(profiles))
	var wg sync.WaitGroup
	for i, profile := range profiles {
		i, profile := i, profile
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot := awgProfilePeerSnapshot{
				Profile:    profile.Name,
				Interface:  profile.Interface,
				UAPISocket: profile.UAPISocket,
			}
			peers, err := listAWGPeerConfigs(profile.UAPISocket)
			if err != nil {
				snapshot.Error = err.Error()
			} else {
				snapshot.Peers = peers
			}
			out[i] = snapshot
		}()
	}
	wg.Wait()
	return out
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
	// AWG does not depend on Xray, so a Docker/Xray failure must not hold back
	// AWG peers, and one failing AWG profile must not hold back the others.
	var errs []error
	for _, profile := range awgProfiles(cfg) {
		desiredPeers, err := writeAWGPeerRegistryForProfile(cfg, st, devices, profile)
		if err != nil {
			errs = append(errs, fmt.Errorf("write awg peer registry %s: %w", profile.Name, err))
			continue
		}
		if profile.UAPISocket != "" {
			if err := syncAWGUAPI(profile.UAPISocket, desiredPeers, cfg.AWGServerKeepalive); err != nil {
				errs = append(errs, fmt.Errorf("sync awg uapi %s: %w", profile.Name, err))
				continue
			}
			slog.Info("awg materialized", "profile", profile.Name, "peers", len(desiredPeers), "uapi_socket", profile.UAPISocket)
		}
	}
	if err := applyXrayConfig(cfg, xrayRaw, len(devices)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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
		normalized, err := normalizeApprovedDevice(device)
		if err != nil {
			// One malformed device must not block every other device on the
			// worker, so it is skipped instead of failing the whole bundle.
			slog.Warn("approved device skipped", "device_id", sanitizeLogValue(device.DeviceID), "err", err)
			continue
		}
		out = append(out, normalized)
	}
	return out, nil
}

func normalizeApprovedDevice(device approvedDevice) (approvedDevice, error) {
	if !validDeviceID(device.DeviceID) {
		return approvedDevice{}, errors.New("device_id contains forbidden characters")
	}
	device.RealityUUID = strings.TrimSpace(device.RealityUUID)
	if !realityUUIDPattern.MatchString(device.RealityUUID) {
		return approvedDevice{}, errors.New("reality_uuid is not a UUID")
	}
	if device.Limits.DownloadMbps < 0 || device.Limits.UploadMbps < 0 || device.Limits.DownloadMbps > maxRateMbps || device.Limits.UploadMbps > maxRateMbps {
		return approvedDevice{}, fmt.Errorf("limits must be in 0..%d Mbps", maxRateMbps)
	}
	device.RealityFlow = strings.TrimSpace(device.RealityFlow)
	if err := validRealityFlow(device.RealityFlow); err != nil {
		return approvedDevice{}, err
	}
	base, err := normalizeAWGCreds(approvedDeviceAWGProfile{AWGPublicKey: device.AWGPublicKey, InternalIP: device.InternalIP, PSK2: device.PSK2})
	if err != nil {
		return approvedDevice{}, err
	}
	device.AWGPublicKey, device.InternalIP, device.PSK2 = base.AWGPublicKey, base.InternalIP, base.PSK2
	if len(device.AWGProfiles) > 0 {
		profiles := make(map[string]approvedDeviceAWGProfile, len(device.AWGProfiles))
		for name, creds := range device.AWGProfiles {
			normalized, err := normalizeAWGCreds(creds)
			if err != nil {
				slog.Warn("approved device awg profile skipped", "device_id", sanitizeLogValue(device.DeviceID), "profile", sanitizeLogValue(name), "err", err)
				continue
			}
			profiles[name] = normalized
		}
		device.AWGProfiles = profiles
	}
	return device, nil
}

func normalizeAWGCreds(creds approvedDeviceAWGProfile) (approvedDeviceAWGProfile, error) {
	creds.AWGPublicKey = strings.TrimSpace(creds.AWGPublicKey)
	if _, err := serverpeer.KeyB64ToHex(creds.AWGPublicKey); err != nil {
		return approvedDeviceAWGProfile{}, fmt.Errorf("awg_public_key: %w", err)
	}
	creds.PSK2 = strings.TrimSpace(creds.PSK2)
	if _, err := serverpeer.KeyB64ToHex(creds.PSK2); err != nil {
		return approvedDeviceAWGProfile{}, fmt.Errorf("psk2: %w", err)
	}
	ip, err := normalizeHostPrefix(creds.InternalIP)
	if err != nil {
		return approvedDeviceAWGProfile{}, fmt.Errorf("internal_ip: %w", err)
	}
	creds.InternalIP = ip
	return creds, nil
}

// normalizeHostPrefix accepts a single host as "a.b.c.d" or "a.b.c.d/32" (or the
// IPv6 equivalents) and returns it in canonical prefix form.
func normalizeHostPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		if prefix.Bits() != prefix.Addr().BitLen() {
			return "", fmt.Errorf("%q is not a single host", value)
		}
		return prefix.String(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("%q is not an IP address", value)
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
}

func validDeviceID(id string) bool {
	if len(id) > 256 || strings.Contains(id, ">>>") {
		return false
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func sanitizeLogValue(value string) string {
	if len(value) > 64 {
		value = value[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, value)
}

func cachedApprovedDevices(stateDir string) []approvedDevice {
	devices, err := loadCachedApprovedDevices(stateDir)
	if err != nil {
		slog.Warn("cached approved_devices ignored", "err", err)
		return nil
	}
	return devices
}

func loadCachedApprovedDevices(stateDir string) ([]approvedDevice, error) {
	path := filepath.Join(stateDir, "orch", "worker-config.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cached worker config: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, errors.New("cached worker config is empty")
	}
	devices, err := approvedDevicesFromWorkerConfig(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse cached worker config: %w", err)
	}
	return devices, nil
}

func filterUnexpiredApprovedDevices(devices []approvedDevice, now time.Time) []approvedDevice {
	out := make([]approvedDevice, 0, len(devices))
	for _, device := range devices {
		if expiresAt, ok := approvedDeviceExpiry(device); ok && !now.Before(expiresAt) {
			slog.Debug("approved device expired; skipping materialization", "device_id", device.DeviceID, "expires_at", expiresAt.Format(time.RFC3339))
			continue
		}
		out = append(out, device)
	}
	return out
}

func writeAWGPeerRegistry(cfg envConfig, st stateFile, devices []approvedDevice) ([]awgDesiredPeer, error) {
	return writeAWGPeerRegistryForProfile(cfg, st, devices, defaultAWGInboundProfile(cfg))
}

func writeAWGPeerRegistryForProfile(cfg envConfig, st stateFile, devices []approvedDevice, profile awgInboundProfile) ([]awgDesiredPeer, error) {
	registry, desired := buildAWGPeerRegistryForProfile(st, devices, profile, !cfg.DisableSmokePeers)
	if err := writeJSONFile(profile.registryPath(cfg.StateDir), registry, 0o600); err != nil {
		return nil, err
	}
	return desired, nil
}

func buildAWGPeerRegistryForProfile(st stateFile, devices []approvedDevice, profile awgInboundProfile, includeSmoke bool) (awgPeerRegistry, []awgDesiredPeer) {
	now := time.Now().UTC()
	expires := time.Now().UTC().Add(3650 * 24 * time.Hour)
	clients := []awgPeerRegistryClient{}
	desired := []awgDesiredPeer{}
	seen := map[string]struct{}{}
	seenIPs := map[string]struct{}{}
	subnet, subnetErr := netip.ParsePrefix(profile.Subnet)
	if includeSmoke && profile.isBase() {
		clients = append(clients, awgPeerRegistryClient{
			WGPublicKey: st.AWG.SmokePublic,
			InternalIP:  st.AWG.SmokeIP,
			PSK2:        st.AWG.SmokePSK,
			ExpiresAt:   expires,
		})
		desired = append(desired, awgDesiredPeer{
			PublicKey: st.AWG.SmokePublic,
			PSK2:      st.AWG.SmokePSK,
			AllowedIP: st.AWG.SmokeIP,
		})
		seen[st.AWG.SmokePublic] = struct{}{}
		seenIPs[st.AWG.SmokeIP] = struct{}{}
	}
	for _, device := range devices {
		creds, ok := approvedDeviceProfileCreds(device, profile.Name)
		if !ok {
			continue
		}
		if _, ok := seen[creds.AWGPublicKey]; ok {
			continue
		}
		if _, ok := seenIPs[creds.InternalIP]; ok {
			slog.Warn("approved device skipped: internal_ip is already assigned", "device_id", sanitizeLogValue(device.DeviceID), "profile", profile.Name, "internal_ip", creds.InternalIP)
			continue
		}
		if subnetErr == nil {
			if ip, err := netip.ParsePrefix(creds.InternalIP); err != nil || !subnet.Masked().Contains(ip.Addr()) {
				slog.Warn("approved device skipped: internal_ip is outside the profile subnet", "device_id", sanitizeLogValue(device.DeviceID), "profile", profile.Name, "internal_ip", creds.InternalIP, "subnet", profile.Subnet)
				continue
			}
		}
		deviceExpires := expires
		if parsed, ok := approvedDeviceExpiry(device); ok {
			if !now.Before(parsed) {
				slog.Debug("approved device expired; skipping AWG peer", "device_id", device.DeviceID, "expires_at", parsed.Format(time.RFC3339))
				continue
			}
			deviceExpires = parsed
		}
		seen[creds.AWGPublicKey] = struct{}{}
		seenIPs[creds.InternalIP] = struct{}{}
		clients = append(clients, awgPeerRegistryClient{
			WGPublicKey:  creds.AWGPublicKey,
			InternalIP:   creds.InternalIP,
			PSK2:         creds.PSK2,
			ExpiresAt:    deviceExpires,
			DownloadMbps: device.Limits.DownloadMbps,
			UploadMbps:   device.Limits.UploadMbps,
		})
		desired = append(desired, awgDesiredPeer{
			PublicKey: creds.AWGPublicKey,
			PSK2:      creds.PSK2,
			AllowedIP: creds.InternalIP,
		})
	}
	return awgPeerRegistry{Clients: clients}, desired
}

func approvedDeviceProfileCreds(device approvedDevice, profileName string) (approvedDeviceAWGProfile, bool) {
	profileName = normalizeAWGProfileName(profileName)
	if profileName == "" || profileName == "awg" {
		if strings.TrimSpace(device.AWGPublicKey) == "" || strings.TrimSpace(device.InternalIP) == "" || strings.TrimSpace(device.PSK2) == "" {
			return approvedDeviceAWGProfile{}, false
		}
		return approvedDeviceAWGProfile{AWGPublicKey: device.AWGPublicKey, InternalIP: device.InternalIP, PSK2: device.PSK2}, true
	}
	if device.AWGProfiles == nil {
		return approvedDeviceAWGProfile{}, false
	}
	creds, ok := device.AWGProfiles[profileName]
	if !ok {
		return approvedDeviceAWGProfile{}, false
	}
	if strings.TrimSpace(creds.AWGPublicKey) == "" || strings.TrimSpace(creds.InternalIP) == "" || strings.TrimSpace(creds.PSK2) == "" {
		return approvedDeviceAWGProfile{}, false
	}
	return creds, true
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
		slog.Warn("approved device has invalid expires_at", "device_id", device.DeviceID, "expires_at", value, "err", err)
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

// syncAWGUAPI converges the device to the desired peers. Only the difference
// against the live peer list is sent, as a single UAPI set operation; if that
// batch fails, peers are retried one by one so a single bad peer is isolated.
func syncAWGUAPI(socketPath string, desired []awgDesiredPeer, keepaliveSec int) error {
	current, err := listAWGPeerConfigs(socketPath)
	if err != nil {
		uapiErrorsTotal.Add(1)
		return err
	}
	currentByHex := make(map[string]awgPeerConfig, len(current))
	for _, peer := range current {
		currentByHex[peer.PublicKeyHex] = peer
	}
	desiredHex := make(map[string]struct{}, len(desired))
	var desiredErr error
	var changed []awgDesiredPeer
	for _, peer := range desired {
		hexKey, err := serverpeer.KeyB64ToHex(peer.PublicKey)
		if err != nil {
			if desiredErr == nil {
				desiredErr = fmt.Errorf("desired peer public key: %w", err)
			}
			continue
		}
		desiredHex[hexKey] = struct{}{}
		if live, ok := currentByHex[hexKey]; ok && awgPeerMatches(live, peer, keepaliveSec) {
			continue
		}
		changed = append(changed, peer)
	}
	var stale []string
	// An incomplete desired set must never remove live peers.
	if desiredErr == nil {
		for _, peer := range current {
			if _, ok := desiredHex[peer.PublicKeyHex]; !ok {
				stale = append(stale, peer.PublicKeyHex)
			}
		}
	}
	if len(changed) == 0 && len(stale) == 0 {
		return desiredErr
	}
	lines, buildErr := awgBatchLines(changed, stale, keepaliveSec)
	if buildErr == nil {
		if err := writeUAPI(socketPath, lines); err == nil {
			return desiredErr
		}
		uapiErrorsTotal.Add(1)
	}
	var errs []error
	for _, pubHex := range stale {
		if err := removeAWGPeerHex(socketPath, pubHex); err != nil {
			uapiErrorsTotal.Add(1)
			errs = append(errs, err)
		}
	}
	for _, peer := range changed {
		if err := addAWGPeer(socketPath, peer, keepaliveSec); err != nil {
			uapiErrorsTotal.Add(1)
			errs = append(errs, err)
		}
	}
	return errors.Join(append([]error{desiredErr}, errs...)...)
}

func awgBatchLines(changed []awgDesiredPeer, stale []string, keepaliveSec int) ([]string, error) {
	lines := []string{"set=1"}
	for _, pubHex := range stale {
		normalized, err := normalizeHexKey(pubHex)
		if err != nil {
			return nil, err
		}
		lines = append(lines, "public_key="+normalized, "remove=true")
	}
	for _, peer := range changed {
		pubHex, err := serverpeer.KeyB64ToHex(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("wg public key: %w", err)
		}
		pskHex, err := serverpeer.KeyB64ToHex(peer.PSK2)
		if err != nil {
			return nil, fmt.Errorf("psk2: %w", err)
		}
		lines = append(lines, serverpeer.PeerUAPILines(pubHex, pskHex, peer.AllowedIP, keepaliveSec)...)
	}
	return append(lines, "", ""), nil
}

// awgPeerMatches reports whether a live peer already has the desired policy.
// The preshared key is compared only when the device reports it.
func awgPeerMatches(live awgPeerConfig, want awgDesiredPeer, keepaliveSec int) bool {
	if live.PersistentKeepalive != int64(keepaliveSec) {
		return false
	}
	if len(live.AllowedIPs) != 1 || strings.TrimSpace(live.AllowedIPs[0]) != strings.TrimSpace(want.AllowedIP) {
		return false
	}
	if live.PresharedKeyHex != "" {
		pskHex, err := serverpeer.KeyB64ToHex(want.PSK2)
		if err != nil || pskHex != live.PresharedKeyHex {
			return false
		}
	}
	return true
}

func reconcileAWGPeers(cfg envConfig, st stateFile) error {
	devices, err := loadCachedApprovedDevices(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("AWG reconcile skipped by anti-wipe guard: %w", err)
	}
	devices = filterUnexpiredApprovedDevices(devices, time.Now().UTC())
	if orchAppliedSeq(cfg.StateDir) > 0 && len(devices) == 0 {
		return errors.New("AWG reconcile skipped by anti-wipe guard: applied worker config has no approved devices")
	}

	type profileResult struct {
		name string
		err  error
	}
	profiles := awgProfiles(cfg)
	results := make(chan profileResult, len(profiles))
	for _, profile := range profiles {
		profile := profile
		go func() {
			results <- profileResult{name: profile.Name, err: reconcileAWGProfile(cfg, st, devices, profile)}
		}()
	}
	var errs []error
	for range profiles {
		result := <-results
		if result.err == nil {
			continue
		}
		slog.Warn("awg reconcile skipped", "profile", result.name, "err", result.err)
		errs = append(errs, fmt.Errorf("profile %s: %w", result.name, result.err))
	}
	return errors.Join(errs...)
}

func reconcileAWGProfile(cfg envConfig, st stateFile, devices []approvedDevice, profile awgInboundProfile) error {
	if strings.TrimSpace(profile.UAPISocket) == "" {
		return errors.New("UAPI socket is not configured")
	}
	_, desired := buildAWGPeerRegistryForProfile(st, devices, profile, !cfg.DisableSmokePeers)
	if len(desired) == 0 {
		return errors.New("desired peer set is empty; refusing destructive sync")
	}
	current, err := listAWGPeerConfigs(profile.UAPISocket)
	if err != nil {
		return err
	}
	drifted, reason, err := awgPeersNeedSync(current, desired, cfg.AWGServerKeepalive)
	if err != nil {
		return err
	}
	if !drifted {
		return nil
	}
	awgPeerPolicyDriftTotal.Add(1)
	slog.Info("awg peer policy drift",
		"profile", profile.Name,
		"reason", reason,
		"current", len(current),
		"desired", len(desired),
		"server_keepalive", cfg.AWGServerKeepalive,
	)
	if err := syncAWGUAPI(profile.UAPISocket, desired, cfg.AWGServerKeepalive); err != nil {
		return fmt.Errorf("repair drift: %w", err)
	}
	slog.Info("awg peer policy reconciled", "profile", profile.Name, "peers", len(desired))
	return nil
}

func awgPeersNeedSync(current []awgPeerConfig, desired []awgDesiredPeer, keepaliveSec int) (bool, string, error) {
	desiredByHex := make(map[string]awgDesiredPeer, len(desired))
	for _, peer := range desired {
		hexKey, err := serverpeer.KeyB64ToHex(peer.PublicKey)
		if err != nil {
			return false, "", fmt.Errorf("desired peer public key: %w", err)
		}
		if _, exists := desiredByHex[hexKey]; exists {
			return false, "", fmt.Errorf("desired peer public key %s is duplicated", hexKey)
		}
		desiredByHex[hexKey] = peer
	}
	currentByHex := make(map[string]awgPeerConfig, len(current))
	for _, peer := range current {
		if _, exists := currentByHex[peer.PublicKeyHex]; exists {
			return true, "duplicate current peer", nil
		}
		currentByHex[peer.PublicKeyHex] = peer
	}
	if len(currentByHex) != len(desiredByHex) {
		return true, "peer set differs", nil
	}
	for hexKey, wanted := range desiredByHex {
		peer, ok := currentByHex[hexKey]
		if !ok {
			return true, "desired peer is missing", nil
		}
		if peer.PersistentKeepalive != int64(keepaliveSec) {
			return true, "persistent keepalive differs", nil
		}
		if !awgPeerMatches(peer, wanted, keepaliveSec) {
			return true, "allowed IP or preshared key differs", nil
		}
	}
	return false, "", nil
}

func addAWGPeer(socketPath string, peer awgDesiredPeer, keepaliveSec int) error {
	pubHex, err := serverpeer.KeyB64ToHex(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("wg public key: %w", err)
	}
	pskHex, err := serverpeer.KeyB64ToHex(peer.PSK2)
	if err != nil {
		return fmt.Errorf("psk2: %w", err)
	}
	lines := []string{"set=1"}
	lines = append(lines, serverpeer.PeerUAPILines(pubHex, pskHex, peer.AllowedIP, keepaliveSec)...)
	return writeUAPI(socketPath, append(lines, "", ""))
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
			peers = append(peers, awgPeerConfig{PublicKeyHex: normalized, PersistentKeepalive: -1})
			current = len(peers) - 1
		case "preshared_key":
			if current >= 0 {
				peers[current].PresharedKeyHex = strings.ToLower(value)
			}
		case "persistent_keepalive_interval":
			if current >= 0 {
				parsed, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("parse persistent keepalive %q: %w", value, err)
				}
				peers[current].PersistentKeepalive = parsed
			}
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
