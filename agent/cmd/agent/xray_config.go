package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

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
			slog.Warn("invalid XRAY_XHTTP_EXTRA_JSON ignored", "err", err)
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
			slog.Warn("approved device skipped for REALITY: duplicate device_id", "device_id", sanitizeLogValue(email))
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
		realitySettings := map[string]any{
			"show":        false,
			"dest":        cfg.RealityDest,
			"xver":        0,
			"serverNames": []string{cfg.CamouflageDomain},
			"privateKey":  st.Reality.PrivateKey,
			"shortIds":    shortIDs,
		}
		if cfg.RealityMaxTimeDiff > 0 {
			// Xray takes milliseconds; 0 (unset) accepts any age.
			realitySettings["maxTimeDiff"] = cfg.RealityMaxTimeDiff.Milliseconds()
		}
		streamSettings := map[string]any{
			"network":         profile.Network,
			"security":        "reality",
			"realitySettings": realitySettings,
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
	// The API listens only on a unix socket in a volume shared with the
	// agent, so it is unreachable over the network, including by clients.
	apiSocket := cfg.XrayAPISocket
	if apiSocket == "" {
		apiSocket = defaultXrayAPISocket
	}
	apiInbound := map[string]any{
		"tag":      "api",
		"listen":   apiSocket,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1", "port": xrayAPIInPort, "network": "unix"},
	}
	xcfg := map[string]any{
		"log":      xrayLogSettings(),
		"inbounds": append(inbounds, apiInbound),
		"outbounds": []any{
			xrayDirectOutbound(cfg),
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
	if dns := xrayDNS(cfg); dns != nil {
		xcfg["dns"] = dns
	}
	return xcfg
}

// xrayConfigRejected is set while the rendered Xray config is refused and the
// last valid one stays in use; self_check reports it.
var xrayConfigRejected atomic.Bool

// xrayLogSettings keeps Xray from recording who connected where. Xray writes
// an access log unless it is explicitly set to "none", and each line would
// carry the client's real address, the destination and the device ID.
func xrayLogSettings() map[string]any {
	return map[string]any{
		"access":   "none",
		"dnsLog":   false,
		"loglevel": "warning",
	}
}

// xrayDirectOutbound connects to the address Xray's own resolver returned.
// With the default AsIs strategy freedom resolves the name again when it
// dials, so a name that answers with a public address for routing and a
// private one for the dial would get past the private-egress rule.
// ForceIPv4 also fails the connection instead of falling back to the system
// resolver when Xray's resolver has no usable answer.
func xrayDirectOutbound(cfg envConfig) map[string]any {
	outbound := map[string]any{"tag": "direct", "protocol": "freedom"}
	if !cfg.AllowPrivateEgress {
		outbound["settings"] = map[string]any{"domainStrategy": "ForceIPv4"}
	}
	return outbound
}

// xrayDNS drops private addresses from every answer, so a public name can
// never resolve to the agent, the host or a metadata service.
func xrayDNS(cfg envConfig) map[string]any {
	if cfg.AllowPrivateEgress {
		return nil
	}
	return map[string]any{
		"queryStrategy": "UseIPv4",
		"servers": []any{map[string]any{
			"address":       "localhost",
			"unexpectedIPs": privateEgressCIDRs,
		}},
	}
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
			"ip":          append(slices.Clone(privateEgressCIDRs), workerAddresses(cfg)...),
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

// errNoShortIDs means the REALITY inbounds would accept no short ID. Xray
// refuses such a config and would restart in a loop, so it is never written.
var errNoShortIDs = errors.New("xray config has no REALITY short IDs")

func xrayConfigBytes(cfg envConfig, st stateFile, devices []approvedDevice) ([]byte, error) {
	if len(realityShortIDs(st, revokedShortIDs(cfg.StateDir))) == 0 {
		xrayConfigRejected.Store(true)
		return nil, errNoShortIDs
	}
	xrayConfigRejected.Store(false)
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
