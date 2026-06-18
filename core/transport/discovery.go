package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	rendezvousNamespace = "rendezvous-v1"
	rendezvousSchema    = 2
	rendezvousPubkey    = ""
)

var forbiddenDiscoveryKeys = map[string]struct{}{
	"internal_ip":        {},
	"internalip":         {},
	"private_key":        {},
	"privatekey":         {},
	"psk2":               {},
	"server_private_key": {},
}

type applyDiscoveredRequest struct {
	EndpointsJSON        string `json:"endpoints_json"`
	EndpointsJSONMinisig string `json:"endpoints_json_minisig,omitempty"`
	Minisig              string `json:"minisig,omitempty"`
	PublicKey            string `json:"public_key,omitempty"`
	Now                  string `json:"now,omitempty"`
	MaxSeenSeq           int64  `json:"max_seen_seq,omitempty"`
	BaseConfigJSON       string `json:"base_config_json,omitempty"`
}

type discoveredBundle struct {
	Schema    int                 `json:"schema"`
	Namespace string              `json:"ns"`
	Seq       int64               `json:"seq"`
	IssuedAt  string              `json:"issued_at"`
	ExpiresAt string              `json:"expires_at"`
	Endpoints discoveredEndpoints `json:"endpoints"`
}

type discoveredEndpoints struct {
	AWG     []discoveredAWGEndpoint     `json:"awg"`
	Reality []discoveredRealityEndpoint `json:"reality"`
}

type discoveredAWGEndpoint struct {
	Priority        int    `json:"priority"`
	Endpoint        string `json:"endpoint"`
	ServerPublicKey string `json:"server_public_key"`
	AWGPreset       preset `json:"awg_preset"`
}

type discoveredRealityEndpoint struct {
	Priority    int    `json:"priority"`
	Transport   string `json:"transport,omitempty"`
	Address     string `json:"address,omitempty"`
	EgressIP    string `json:"egress_ip,omitempty"`
	Port        int    `json:"port,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	Flow        string `json:"flow,omitempty"`
	Security    string `json:"security,omitempty"`
	Network     string `json:"network,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type applyDiscoveredResult struct {
	OK         bool                       `json:"ok"`
	Error      string                     `json:"error,omitempty"`
	Seq        int64                      `json:"seq,omitempty"`
	ConfigJSON string                     `json:"config_json,omitempty"`
	EgressIP   string                     `json:"egress_ip,omitempty"`
	Reality    *discoveredRealityEndpoint `json:"reality,omitempty"`
}

func ApplyDiscoveredEndpoints(requestJSON string) string {
	result, err := applyDiscoveredEndpoints(requestJSON)
	if err != nil {
		return encodeApplyDiscoveredResult(applyDiscoveredResult{OK: false, Error: err.Error()})
	}
	return encodeApplyDiscoveredResult(result)
}

func applyDiscoveredEndpoints(requestJSON string) (applyDiscoveredResult, error) {
	var req applyDiscoveredRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return applyDiscoveredResult{}, fmt.Errorf("parse request json: %w", err)
	}
	if strings.TrimSpace(req.EndpointsJSON) == "" {
		return applyDiscoveredResult{}, errors.New("endpoints_json is required")
	}
	signature := firstNonEmpty(req.EndpointsJSONMinisig, req.Minisig)
	if strings.TrimSpace(signature) == "" {
		return applyDiscoveredResult{}, errors.New("endpoints minisig is required")
	}
	pubkey := strings.TrimSpace(req.PublicKey)
	if pubkey == "" {
		return applyDiscoveredResult{}, errors.New("public_key is required")
	}
	if err := verifyMinisignResult(req.EndpointsJSON, signature, pubkey); err != nil {
		return applyDiscoveredResult{}, err
	}
	if err := rejectForbiddenDiscoveryKeys([]byte(req.EndpointsJSON)); err != nil {
		return applyDiscoveredResult{}, err
	}
	var bundle discoveredBundle
	if err := json.Unmarshal([]byte(req.EndpointsJSON), &bundle); err != nil {
		return applyDiscoveredResult{}, fmt.Errorf("parse endpoints json: %w", err)
	}
	now, err := discoveryNow(req.Now)
	if err != nil {
		return applyDiscoveredResult{}, err
	}
	if err := validateDiscoveredBundle(bundle, req.MaxSeenSeq, now); err != nil {
		return applyDiscoveredResult{}, err
	}
	awg, err := selectAWGEndpoint(bundle.Endpoints.AWG)
	if err != nil {
		return applyDiscoveredResult{}, err
	}
	reality := selectRealityEndpoint(bundle.Endpoints.Reality)
	baseJSON := req.BaseConfigJSON
	if baseJSON == "" {
		pendingProvision.Lock()
		baseJSON = pendingProvision.configJSON
		pendingProvision.Unlock()
	}
	if baseJSON == "" {
		return applyDiscoveredResult{}, errors.New("provisioned config is missing")
	}
	mergedJSON, err := mergeDiscoveredAWGConfig(baseJSON, awg)
	if err != nil {
		return applyDiscoveredResult{}, err
	}
	pendingProvision.Lock()
	pendingProvision.configJSON = mergedJSON
	pendingProvision.Unlock()
	result := applyDiscoveredResult{
		OK:         true,
		Seq:        bundle.Seq,
		ConfigJSON: mergedJSON,
	}
	if reality != nil {
		result.Reality = reality
		result.EgressIP = reality.EgressIP
	}
	return result, nil
}

func validateDiscoveredBundle(bundle discoveredBundle, maxSeenSeq int64, now time.Time) error {
	if bundle.Schema != rendezvousSchema {
		return fmt.Errorf("unsupported rendezvous schema: %d", bundle.Schema)
	}
	if bundle.Namespace != rendezvousNamespace {
		return fmt.Errorf("invalid rendezvous namespace: %q", bundle.Namespace)
	}
	if bundle.Seq < 0 {
		return errors.New("rendezvous seq must be non-negative")
	}
	if bundle.Seq < maxSeenSeq {
		return fmt.Errorf("rendezvous rollback: seq=%d max_seen_seq=%d", bundle.Seq, maxSeenSeq)
	}
	issuedAt, err := parseRendezvousTime(bundle.IssuedAt, "issued_at")
	if err != nil {
		return err
	}
	expiresAt, err := parseRendezvousTime(bundle.ExpiresAt, "expires_at")
	if err != nil {
		return err
	}
	if !expiresAt.After(issuedAt) {
		return errors.New("expires_at must be after issued_at")
	}
	if now.Before(issuedAt) {
		return errors.New("rendezvous bundle is not issued yet")
	}
	if !now.Before(expiresAt) {
		return errors.New("rendezvous bundle expired")
	}
	return nil
}

func mergeDiscoveredAWGConfig(baseJSON string, awg discoveredAWGEndpoint) (string, error) {
	if _, err := parseConfig(baseJSON); err != nil {
		return "", fmt.Errorf("base config: %w", err)
	}
	var base config
	if err := json.Unmarshal([]byte(baseJSON), &base); err != nil {
		return "", fmt.Errorf("parse base config json: %w", err)
	}
	base.Endpoint = strings.TrimSpace(awg.Endpoint)
	base.ServerPublicKey = strings.TrimSpace(awg.ServerPublicKey)
	base.AWGPreset = awg.AWGPreset
	raw, err := json.Marshal(base)
	if err != nil {
		return "", err
	}
	if _, err := parseConfig(string(raw)); err != nil {
		return "", fmt.Errorf("merged config: %w", err)
	}
	return string(raw), nil
}

func selectAWGEndpoint(endpoints []discoveredAWGEndpoint) (discoveredAWGEndpoint, error) {
	if len(endpoints) == 0 {
		return discoveredAWGEndpoint{}, errors.New("no awg endpoints in bundle")
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		return endpoints[i].Priority < endpoints[j].Priority
	})
	selected := endpoints[0]
	if strings.TrimSpace(selected.Endpoint) == "" ||
		strings.TrimSpace(selected.ServerPublicKey) == "" {
		return discoveredAWGEndpoint{}, errors.New("selected awg endpoint is incomplete")
	}
	if _, err := base64KeyToHex(selected.ServerPublicKey); err != nil {
		return discoveredAWGEndpoint{}, fmt.Errorf("discovered server_public_key: %w", err)
	}
	if err := validatePreset(selected.AWGPreset, defaultMTU); err != nil {
		return discoveredAWGEndpoint{}, fmt.Errorf("discovered awg_preset: %w", err)
	}
	return selected, nil
}

func selectRealityEndpoint(endpoints []discoveredRealityEndpoint) *discoveredRealityEndpoint {
	if len(endpoints) == 0 {
		return nil
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		return endpoints[i].Priority < endpoints[j].Priority
	})
	return &endpoints[0]
}

func discoveryNow(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Now().UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("now: %w", err)
	}
	return parsed.UTC(), nil
}

func parseRendezvousTime(value string, field string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", field, err)
	}
	return parsed.UTC(), nil
}

func rejectForbiddenDiscoveryKeys(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	return rejectForbiddenDiscoveryValue(value, "")
}

func rejectForbiddenDiscoveryValue(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			if _, forbidden := forbiddenDiscoveryKeys[normalized]; forbidden {
				if path == "" {
					return fmt.Errorf("forbidden discovery field: %s", key)
				}
				return fmt.Errorf("forbidden discovery field: %s.%s", path, key)
			}
			nextPath := key
			if path != "" {
				nextPath = path + "." + key
			}
			if err := rejectForbiddenDiscoveryValue(child, nextPath); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range typed {
			if err := rejectForbiddenDiscoveryValue(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func encodeApplyDiscoveredResult(result applyDiscoveredResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal apply discovered result"}`
	}
	return string(raw)
}
