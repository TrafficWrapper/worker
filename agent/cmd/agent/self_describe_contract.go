package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Limits of the worker self_describe v1 contract. The orchestrator drops
// anything outside them, so the worker refuses to start with settings that
// would produce such a document.
const (
	selfDescribeMaxString   = 256
	selfDescribeMaxProfiles = 32
	selfDescribeMaxBytes    = 64 << 10
)

// workerCapabilities lists the optional behaviors this worker implements. It
// is published in self_describe and sent with every config pull.
var workerCapabilities = []string{"reality_flow", "desired_state_enabled", "revoked_status", "apk_fetch_v1"}

// selfDescribeForbiddenKeys must never appear anywhere in self_describe; a
// worker that sends one is dropped from client bundles.
var selfDescribeForbiddenKeys = map[string]struct{}{
	"private_key":        {},
	"privatekey":         {},
	"psk2":               {},
	"internal_ip":        {},
	"internalip":         {},
	"server_private_key": {},
}

func validateSelfDescribeEnv(cfg envConfig) error {
	if cfg.PublicAddress != "" && !validHostOrIP(cfg.PublicAddress) {
		return fmt.Errorf("PUBLIC_ADDRESS must be a hostname or IP address, got %q", cfg.PublicAddress)
	}
	if !validHostOrIP(cfg.CamouflageDomain) {
		return fmt.Errorf("CAMOUFLAGE_DOMAIN must be a hostname, got %q", cfg.CamouflageDomain)
	}
	for name, raw := range map[string]string{
		"ORCH_URL":         cfg.OrchURL,
		"WORKER_AGENT_URL": cfg.WorkerAgentURL,
		"DISTRIBUTOR_URL":  cfg.DistributorURL,
	} {
		if raw == "" {
			continue
		}
		if len(raw) > selfDescribeMaxString {
			return fmt.Errorf("%s is longer than %d characters", name, selfDescribeMaxString)
		}
		if u, err := url.Parse(raw); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s must be an http or https URL", name)
		}
	}
	for name, value := range map[string]string{
		"EGRESS_IP":       cfg.EgressIP,
		"REALITY_DEST":    cfg.RealityDest,
		"XRAY_XHTTP_PATH": cfg.XHTTPPath,
		"XRAY_XHTTP_MODE": cfg.XHTTPMode,
		"XRAY_XHTTP_HOST": cfg.XHTTPHost,
	} {
		if len(value) > selfDescribeMaxString {
			return fmt.Errorf("%s is longer than %d characters", name, selfDescribeMaxString)
		}
	}
	if n := len(cfg.RealityProfiles) + 1; n > selfDescribeMaxProfiles {
		return fmt.Errorf("REALITY_INBOUNDS: %d REALITY profiles, at most %d", n, selfDescribeMaxProfiles)
	}
	for _, p := range cfg.RealityProfiles {
		for _, value := range []string{p.Name, p.XHTTPPath, p.XHTTPMode, p.XHTTPHost} {
			if len(value) > selfDescribeMaxString {
				return fmt.Errorf("REALITY_INBOUNDS profile %q has a value longer than %d characters", p.Name, selfDescribeMaxString)
			}
		}
	}
	if len(cfg.AWGProfiles) > selfDescribeMaxProfiles {
		return fmt.Errorf("AWG_INBOUNDS: %d profiles, at most %d", len(cfg.AWGProfiles), selfDescribeMaxProfiles)
	}
	return nil
}

// validHostOrIP accepts an IP address or an RFC 1123 host name.
func validHostOrIP(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return true
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// checkSelfDescribe builds the document the way the orchestrator receives it
// and checks it against the contract, so a worker whose settings produce an
// oversized or malformed document fails at startup instead of being dropped.
func checkSelfDescribe(cfg envConfig, st stateFile) error {
	raw, err := json.Marshal(selfDescribe(cfg, st))
	if err != nil {
		return err
	}
	if len(raw) > selfDescribeMaxBytes {
		return fmt.Errorf("self_describe is %d bytes, over the %d byte limit; use fewer REALITY_INBOUNDS/AWG_INBOUNDS profiles or shorter values", len(raw), selfDescribeMaxBytes)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	return checkSelfDescribeContract(doc, "self_describe")
}

// checkSelfDescribeContract reports the first violation of the contract
// limits in an already built document.
func checkSelfDescribeContract(doc any, path string) error {
	switch v := doc.(type) {
	case map[string]any:
		for key, child := range v {
			if _, bad := selfDescribeForbiddenKeys[strings.ToLower(key)]; bad {
				return fmt.Errorf("%s.%s is a forbidden key", path, key)
			}
			if err := checkSelfDescribeContract(child, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		if len(v) > selfDescribeMaxProfiles {
			return fmt.Errorf("%s has %d items, at most %d", path, len(v), selfDescribeMaxProfiles)
		}
		for i, child := range v {
			if err := checkSelfDescribeContract(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case []string:
		items := make([]any, len(v))
		for i, s := range v {
			items[i] = s
		}
		return checkSelfDescribeContract(items, path)
	case string:
		if len(v) > selfDescribeMaxString {
			return fmt.Errorf("%s is longer than %d characters", path, selfDescribeMaxString)
		}
	}
	return nil
}
