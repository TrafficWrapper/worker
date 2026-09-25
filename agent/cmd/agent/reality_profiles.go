package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
)

const (
	realityBaseProfileName = "reality"
	realityBaseInboundTag  = "reality-in"
	realityTagPrefix       = "reality-"
	flowVision             = "xtls-rprx-vision"
	// realityCohortCount short IDs are generated per worker. The orchestrator
	// assigns each device to one, so a leaked cohort can be revoked without
	// touching the others.
	realityCohortCount = 16
)

// realityProfile is one REALITY inbound. The base profile comes from the
// XRAY_* variables; REALITY_INBOUNDS adds more, for example XHTTP on another
// port as a fallback when raw TCP is throttled.
type realityProfile struct {
	Name       string `json:"name"`
	Network    string `json:"network"`
	ListenPort int    `json:"listen_port"`
	PublicPort int    `json:"public_port,omitempty"`
	XHTTPPath  string `json:"xhttp_path,omitempty"`
	XHTTPMode  string `json:"xhttp_mode,omitempty"`
	XHTTPHost  string `json:"xhttp_host,omitempty"`
}

func (p realityProfile) tag() string {
	if p.Name == realityBaseProfileName {
		return realityBaseInboundTag
	}
	return realityTagPrefix + p.Name
}

func (p realityProfile) supportsVision() bool {
	return p.Network == "tcp"
}

func baseRealityProfile(cfg envConfig) realityProfile {
	return realityProfile{
		Name:       realityBaseProfileName,
		Network:    realityNetwork(cfg),
		ListenPort: xrayInPort,
		PublicPort: cfg.XrayPort,
		XHTTPPath:  strings.TrimSpace(cfg.XHTTPPath),
		XHTTPMode:  strings.TrimSpace(cfg.XHTTPMode),
		XHTTPHost:  xhttpHost(cfg),
	}
}

func realityProfiles(cfg envConfig) []realityProfile {
	return append([]realityProfile{baseRealityProfile(cfg)}, cfg.RealityProfiles...)
}

func parseRealityProfiles(raw string) ([]realityProfile, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var profiles []realityProfile
	if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
		return nil, fmt.Errorf("parse REALITY_INBOUNDS: %w", err)
	}
	seenNames := map[string]struct{}{realityBaseProfileName: {}}
	seenPorts := map[int]struct{}{xrayInPort: {}, xrayAPIInPort: {}}
	for i := range profiles {
		p := &profiles[i]
		p.Name = normalizeAWGProfileName(p.Name)
		if p.Name == "" || p.Name == "in" {
			return nil, fmt.Errorf("REALITY_INBOUNDS[%d].name is invalid", i)
		}
		if _, dup := seenNames[p.Name]; dup {
			return nil, fmt.Errorf("REALITY_INBOUNDS profile %q is duplicated", p.Name)
		}
		seenNames[p.Name] = struct{}{}
		switch p.Network = strings.ToLower(strings.TrimSpace(p.Network)); p.Network {
		case "", "tcp":
			p.Network = "tcp"
		case "xhttp":
		default:
			return nil, fmt.Errorf("REALITY_INBOUNDS[%d].network must be tcp or xhttp", i)
		}
		if p.ListenPort < 1025 || p.ListenPort > 65535 {
			return nil, fmt.Errorf("REALITY_INBOUNDS[%d].listen_port must be in 1025..65535", i)
		}
		if _, dup := seenPorts[p.ListenPort]; dup {
			return nil, fmt.Errorf("REALITY_INBOUNDS[%d].listen_port %d is already used", i, p.ListenPort)
		}
		seenPorts[p.ListenPort] = struct{}{}
		if p.PublicPort == 0 {
			p.PublicPort = p.ListenPort
		}
		if p.PublicPort < 1 || p.PublicPort > 65535 {
			return nil, fmt.Errorf("REALITY_INBOUNDS[%d].public_port must be in 1..65535", i)
		}
		if p.Network == "xhttp" && !strings.HasPrefix(p.XHTTPPath, "/") {
			return nil, fmt.Errorf("REALITY_INBOUNDS[%d].xhttp_path must start with /", i)
		}
	}
	return profiles, nil
}

func realityXHTTPSettings(p realityProfile) map[string]any {
	settings := map[string]any{"path": p.XHTTPPath, "mode": p.XHTTPMode}
	if p.XHTTPHost != "" {
		settings["host"] = p.XHTTPHost
	}
	return settings
}

// ensureRealityCohorts backfills cohort short IDs for workers bootstrapped
// before cohorts existed.
func ensureRealityCohorts(st *stateFile) bool {
	if len(st.Reality.CohortShortIDs) >= realityCohortCount {
		return false
	}
	for len(st.Reality.CohortShortIDs) < realityCohortCount {
		st.Reality.CohortShortIDs = append(st.Reality.CohortShortIDs, randHex(8))
	}
	return true
}

// realityShortIDs lists the short IDs the REALITY inbounds accept: the base
// one plus every cohort that the orchestrator has not revoked. The base short
// ID cannot be revoked: every client without a cohort uses it, and without
// it the list could end up empty.
func realityShortIDs(st stateFile, revoked []string) []string {
	base := strings.ToLower(strings.TrimSpace(st.Reality.ShortID))
	skip := make(map[string]struct{}, len(revoked))
	for _, id := range revoked {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == base {
			slog.Warn("revocation of the base REALITY short ID ignored")
			continue
		}
		skip[id] = struct{}{}
	}
	ids := []string{}
	seen := map[string]struct{}{}
	for _, id := range append([]string{st.Reality.ShortID}, st.Reality.CohortShortIDs...) {
		id = strings.ToLower(id)
		if id == "" {
			continue
		}
		if _, ok := skip[id]; ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) > 1 {
		sort.Strings(ids[1:])
	}
	return ids
}

// publishedCohortShortIDs returns every cohort short ID in generation order,
// revoked ones included. Clients pick their slot by index into this list, so
// its length and order must never change; revocation only removes an ID from
// what Xray accepts.
func publishedCohortShortIDs(st stateFile) []string {
	out := make([]string, 0, len(st.Reality.CohortShortIDs))
	for _, id := range st.Reality.CohortShortIDs {
		out = append(out, strings.ToLower(id))
	}
	return out
}

// revokedShortIDs reads the revocation list from the applied worker config.
// The config file is written before devices are materialized, so both the
// startup render and the apply path see the same list.
func revokedShortIDs(stateDir string) []string {
	if stateDir == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, "orch", "worker-config.json"))
	if err != nil {
		return nil
	}
	var doc struct {
		DesiredState struct {
			RevokedShortIDs []string `json:"revoked_short_ids"`
		} `json:"desired_state"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	return doc.DesiredState.RevokedShortIDs
}

func validRealityFlow(flow string) error {
	switch flow {
	case "", flowVision:
		return nil
	default:
		return errors.New("reality_flow must be empty or " + flowVision)
	}
}

// xhttpHostMismatch is set when an XHTTP inbound expects a Host other than
// the camouflage domain. The orchestrator publishes routes with the
// camouflage domain, so such an inbound answers clients with 404.
var xhttpHostMismatch atomic.Bool

// checkXHTTPHosts warns about XHTTP inbounds whose Host differs from
// CAMOUFLAGE_DOMAIN and reports them in self_check. They stay published.
func checkXHTTPHosts(cfg envConfig) []string {
	var mismatched []string
	for _, p := range realityProfiles(cfg) {
		if p.Network != "xhttp" || p.XHTTPHost == "" || strings.EqualFold(p.XHTTPHost, strings.TrimSpace(cfg.CamouflageDomain)) {
			continue
		}
		mismatched = append(mismatched, p.Name)
		slog.Warn("XHTTP host differs from CAMOUFLAGE_DOMAIN; clients using the published route will get 404", "profile", p.Name, "xhttp_host", p.XHTTPHost, "camouflage_domain", cfg.CamouflageDomain)
	}
	xhttpHostMismatch.Store(len(mismatched) > 0)
	return mismatched
}
