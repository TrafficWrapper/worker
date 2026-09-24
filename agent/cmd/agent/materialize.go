package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/serverpeer"
)

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
		ExpiresAt *string `json:"expires_at,omitempty"`
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
			log.Printf("awg materialized profile=%s peers=%d via %s", profile.Name, len(desiredPeers), profile.UAPISocket)
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
			log.Printf("approved device %q skipped: %v", sanitizeLogValue(device.DeviceID), err)
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
				log.Printf("approved device %q awg profile %q skipped: %v", sanitizeLogValue(device.DeviceID), sanitizeLogValue(name), err)
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
	if _, err := base64KeyToHex(creds.AWGPublicKey); err != nil {
		return approvedDeviceAWGProfile{}, fmt.Errorf("awg_public_key: %w", err)
	}
	creds.PSK2 = strings.TrimSpace(creds.PSK2)
	if _, err := base64KeyToHex(creds.PSK2); err != nil {
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
		log.Printf("cached approved_devices ignored: %v", err)
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
			logDebugf("approved device %s expired at %s; skipping materialization", device.DeviceID, expiresAt.Format(time.RFC3339))
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
			log.Printf("approved device %s skipped for profile %s: internal_ip %s is already assigned", sanitizeLogValue(device.DeviceID), profile.Name, creds.InternalIP)
			continue
		}
		if subnetErr == nil {
			if ip, err := netip.ParsePrefix(creds.InternalIP); err != nil || !subnet.Masked().Contains(ip.Addr()) {
				log.Printf("approved device %s skipped for profile %s: internal_ip %s is outside %s", sanitizeLogValue(device.DeviceID), profile.Name, creds.InternalIP, profile.Subnet)
				continue
			}
		}
		deviceExpires := expires
		if parsed, ok := approvedDeviceExpiry(device); ok {
			if !now.Before(parsed) {
				logDebugf("approved device %s expired at %s; skipping AWG peer", device.DeviceID, parsed.Format(time.RFC3339))
				continue
			}
			deviceExpires = parsed
		}
		seen[creds.AWGPublicKey] = struct{}{}
		seenIPs[creds.InternalIP] = struct{}{}
		clients = append(clients, awgPeerRegistryClient{
			WGPublicKey: creds.AWGPublicKey,
			InternalIP:  creds.InternalIP,
			PSK2:        creds.PSK2,
			ExpiresAt:   deviceExpires,
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
		log.Printf("approved device %s has invalid expires_at %q: %v", device.DeviceID, value, err)
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
		hexKey, err := base64KeyToHex(peer.PublicKey)
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
		pubHex, err := base64KeyToHex(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("wg public key: %w", err)
		}
		pskHex, err := base64KeyToHex(peer.PSK2)
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
		pskHex, err := base64KeyToHex(want.PSK2)
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
		log.Printf("awg reconcile profile=%s skipped: %v", result.name, result.err)
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
	log.Printf(
		"awg peer policy drift profile=%s reason=%s current=%d desired=%d server_keepalive=%d",
		profile.Name,
		reason,
		len(current),
		len(desired),
		cfg.AWGServerKeepalive,
	)
	if err := syncAWGUAPI(profile.UAPISocket, desired, cfg.AWGServerKeepalive); err != nil {
		return fmt.Errorf("repair drift: %w", err)
	}
	log.Printf("awg peer policy reconciled profile=%s peers=%d", profile.Name, len(desired))
	return nil
}

func awgPeersNeedSync(current []awgPeerConfig, desired []awgDesiredPeer, keepaliveSec int) (bool, string, error) {
	desiredByHex := make(map[string]awgDesiredPeer, len(desired))
	for _, peer := range desired {
		hexKey, err := base64KeyToHex(peer.PublicKey)
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
	pubHex, err := base64KeyToHex(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("wg public key: %w", err)
	}
	pskHex, err := base64KeyToHex(peer.PSK2)
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
	client := dockerUnixClient(socketPath, 15*time.Second)
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
	discovered, err := discoverDockerContainerByComposeService(client, "xray", true)
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

// discoverDockerContainerByComposeService only looks inside the agent's own
// compose project, so another stack's (or a stale) xray is never touched.
func discoverDockerContainerByComposeService(client *http.Client, service string, includeStopped bool) (string, error) {
	project, err := ownComposeProject(client)
	if err != nil {
		return "", err
	}
	filterRaw, err := json.Marshal(map[string][]string{
		"label": {"com.docker.compose.service=" + service, "com.docker.compose.project=" + project},
	})
	if err != nil {
		return "", err
	}
	endpoint := "http://docker/containers/json?filters=" + url.QueryEscape(string(filterRaw))
	if includeStopped {
		endpoint += "&all=true"
	}
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
	if len(containers) > 1 {
		return "", fmt.Errorf("compose project %q has %d %s containers; set XRAY_CONTAINER_NAME", project, len(containers), service)
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

func ownComposeProject(client *http.Client) (string, error) {
	self, err := os.Hostname()
	if err != nil || strings.TrimSpace(self) == "" {
		return "", errors.New("cannot determine own container id")
	}
	req, err := http.NewRequest(http.MethodGet, "http://docker/containers/"+url.PathEscape(self)+"/json", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("inspect own container %s: http %d", self, resp.StatusCode)
	}
	var inspected struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&inspected); err != nil {
		return "", err
	}
	project := inspected.Config.Labels["com.docker.compose.project"]
	if project == "" {
		return "", errors.New("agent is not running in a compose project")
	}
	return project, nil
}
