package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func selfDescribe(cfg envConfig, st stateFile) map[string]any {
	reality := map[string]any{
		"transport":   "REALITY",
		"address":     cfg.PublicAddress,
		"address_v6":  cfg.PublicAddressV6,
		"port":        cfg.XrayPort,
		"serverName":  cfg.CamouflageDomain,
		"server_name": cfg.CamouflageDomain,
		"dest":        cfg.RealityDest,
		"publicKey":   st.Reality.PublicKey,
		"public_key":  st.Reality.PublicKey,
		"shortId":     st.Reality.ShortID,
		"short_id":    st.Reality.ShortID,
		"flow":        "",
		"security":    "reality",
		"network":     realityNetwork(cfg),
		"fingerprint": "chrome",
		"spiderX":     "/",
	}
	if xhttp := xhttpSettings(cfg); xhttp != nil {
		reality["xhttp"] = xhttp
	}
	cohorts := publishedCohortShortIDs(st)
	reality["cohort_short_ids"] = cohorts
	realityProfilePayloads := []any{}
	for _, profile := range realityProfiles(cfg) {
		payload := map[string]any{
			"name":        profile.Name,
			"address":     cfg.PublicAddress,
			"address_v6":  cfg.PublicAddressV6,
			"port":        profile.PublicPort,
			"network":     profile.Network,
			"server_name": cfg.CamouflageDomain,
			"public_key":  st.Reality.PublicKey,
			"short_id":    st.Reality.ShortID,
			"flows":       []string{""},
		}
		if profile.supportsVision() {
			payload["flows"] = []string{"", flowVision}
		}
		if profile.Network == "xhttp" {
			payload["xhttp"] = realityXHTTPSettings(profile)
		}
		realityProfilePayloads = append(realityProfilePayloads, payload)
	}
	awgProfilePayloads := make([]any, 0, len(awgProfiles(cfg)))
	for _, profile := range awgProfiles(cfg) {
		awgProfilePayloads = append(awgProfilePayloads, awgSelfDescribe(cfg, st, profile))
	}
	baseAWG := awgSelfDescribe(cfg, st, baseAWGProfile(cfg))
	out := map[string]any{
		"schema":           "trafficwrapper-worker-p0",
		"hostname":         st.Hostname,
		"egress_ip":        cfg.EgressIP,
		"orch_url":         cfg.OrchURL,
		"agent_url":        cfg.WorkerAgentURL,
		"distributor_url":  cfg.DistributorURL,
		"standalone":       cfg.OrchURL == "",
		"dialect_id":       st.DialectID,
		"capacity":         cfg.Capacity,
		"protocols":        []string{"REALITY", "AWG"},
		"reality":          reality,
		"reality_profiles": realityProfilePayloads,
		"awg":              baseAWG,
		"awg_profiles":     awgProfilePayloads,
		"health":           healthSnapshot(),
		"orchestrator": map[string]any{
			"noise_xk_ready":  true,
			"pull_ready":      true,
			"nudge_ack_ready": true,
		},
		"capabilities": append([]string(nil), workerCapabilities...),
	}
	if apk := distributedAPKInfo(cfg.StateDir); len(apk) > 0 {
		out["distributed_apk"] = apk
	}
	return out
}

func awgSelfDescribe(cfg envConfig, st stateFile, profile awgInboundProfile) map[string]any {
	return map[string]any{
		"profile":           profile.Name,
		"name":              profile.Name,
		"address":           cfg.PublicAddress,
		"endpoint":          net.JoinHostPort(cfg.PublicAddress, strconv.Itoa(profile.PublicPort)),
		"endpoint_v6":       endpointV6(cfg, profile.PublicPort),
		"public_key":        st.AWG.PublicKey,
		"server_public":     st.AWG.PublicKey,
		"server_public_key": st.AWG.PublicKey,
		"port":              profile.PublicPort,
		"listen_port":       profile.ListenPort,
		"interface":         profile.Interface,
		"subnet":            profile.Subnet,
		"gateway":           profile.Gateway,
		"dns":               awgProfileDNS(cfg, profile),
		"min_version_code":  profile.MinVersionCode,
		"dialect":           profileDialect(st, profile),
		"dialect_id":        profileDialectID(st, profile),
		"smoke_peer_config": "/worker-state/smoke/awg-peer.conf",
	}
}

func distributedAPKInfo(stateDir string) map[string]any {
	twDir := filepath.Join(stateDir, "distributor", "tw")
	for _, path := range []string{
		filepath.Join(twDir, "update-manifest.json"),
		filepath.Join(twDir, "version.json"),
	} {
		raw, err := os.ReadFile(path)
		if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		var root map[string]any
		if err := json.Unmarshal(raw, &root); err != nil {
			continue
		}
		seq := int64FromAny(root["seq"])
		if nested, ok := root["distributed_apk"].(map[string]any); ok {
			root = nested
		}
		if v := int64FromAny(root["seq"]); v > 0 {
			seq = v
		}
		apk := map[string]any{}
		if v := stringFromAny(root["apk_sha256"]); v != "" {
			apk["apk_sha256"] = strings.ToLower(v)
		}
		if v := int64FromAny(root["version_code"]); v > 0 {
			apk["version_code"] = v
		}
		if v := stringFromAny(root["version_name"]); v != "" {
			apk["version_name"] = v
		}
		if v := stringFromAny(root["apk_name"]); v != "" {
			apk["apk_name"] = filepath.Base(v)
		}
		if len(apk) > 0 {
			if seq > 0 {
				apk["seq"] = seq
			}
			return apk
		}
	}
	return nil
}

// publicAddressV6 validates PUBLIC_ADDRESS_V6; "auto" asks an IPv6-only echo
// service. Docker publishes ports on IPv6 too, so an IPv6 endpoint works as
// soon as the host has a global address, and it often stays reachable when
// the provider's IPv4 range is blocked.
func publicAddressV6(value string) (string, error) {
	value = strings.TrimSpace(value)
	switch value {
	case "":
		return "", nil
	case "auto":
		return detectPublicIPv6(), nil
	}
	addr, err := netip.ParseAddr(strings.Trim(value, "[]"))
	if err != nil || !addr.Is6() || addr.Is4In6() || !isPublicIP(addr.String()) {
		return "", fmt.Errorf("PUBLIC_ADDRESS_V6 must be a global IPv6 address or auto, got %q", value)
	}
	return addr.String(), nil
}

var ipv6EchoURL = "https://api6.ipify.org"

func detectPublicIPv6() string {
	ip := fetchEchoIP(ipv6EchoURL)
	if addr, err := netip.ParseAddr(ip); err == nil && addr.Is6() && !addr.Is4In6() {
		return addr.String()
	}
	return ""
}

// awgProfileDNS advertises the in-tunnel resolver (the dns compose profile,
// which runs in the base awg-gw network namespace).
func awgProfileDNS(cfg envConfig, profile awgInboundProfile) []string {
	if !cfg.DNSEnabled || !profile.isBase() {
		return []string{}
	}
	return []string{profile.Gateway}
}

func endpointV6(cfg envConfig, port int) string {
	if cfg.PublicAddressV6 == "" {
		return ""
	}
	return net.JoinHostPort(cfg.PublicAddressV6, strconv.Itoa(port))
}
