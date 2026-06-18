package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"aead.dev/minisign"
)

const (
	rendezvousNamespace = "rendezvous-v1"
	rendezvousSchema    = 2
)

var forbiddenDiscoveryKeys = map[string]struct{}{
	"internal_ip":        {},
	"internalip":         {},
	"private_key":        {},
	"privatekey":         {},
	"psk2":               {},
	"server_private_key": {},
}

type minisignVerifyResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type applyDiscoveredRequest struct {
	EndpointsJSON        string `json:"endpoints_json"`
	EndpointsJSONMinisig string `json:"endpoints_json_minisig,omitempty"`
	Minisig              string `json:"minisig,omitempty"`
	PublicKey            string `json:"public_key,omitempty"`
	Now                  string `json:"now,omitempty"`
	MaxSeenSeq           int64  `json:"max_seen_seq,omitempty"`
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
	AWG     []discoveredEndpoint `json:"awg"`
	Reality []discoveredEndpoint `json:"reality"`
}

type discoveredEndpoint struct {
	Priority int `json:"priority"`
}

type applyDiscoveredResult struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Seq      int64  `json:"seq,omitempty"`
	Selected string `json:"selected,omitempty"`
}

func VerifyMinisign(message string, signature string, publicKey string) string {
	if err := verifyMinisign(message, signature, publicKey); err != nil {
		return encode(minisignVerifyResult{OK: false, Error: err.Error()})
	}
	return encode(minisignVerifyResult{OK: true})
}

func verifyMinisign(message string, signature string, publicKey string) error {
	var pub minisign.PublicKey
	if err := pub.UnmarshalText([]byte(publicKey)); err != nil {
		return errors.New("invalid public key")
	}
	if !minisign.Verify(pub, []byte(message), []byte(signature)) {
		return errors.New("invalid signature")
	}
	return nil
}

func ApplyDiscoveredEndpoints(requestJSON string) string {
	var req applyDiscoveredRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return encode(applyDiscoveredResult{OK: false, Error: "parse request json: " + err.Error()})
	}
	if strings.TrimSpace(req.EndpointsJSON) == "" {
		return encode(applyDiscoveredResult{OK: false, Error: "endpoints_json is required"})
	}
	signature := firstNonEmpty(req.EndpointsJSONMinisig, req.Minisig)
	if strings.TrimSpace(signature) == "" {
		return encode(applyDiscoveredResult{OK: false, Error: "endpoints minisig is required"})
	}
	if strings.TrimSpace(req.PublicKey) == "" {
		return encode(applyDiscoveredResult{OK: false, Error: "public_key is required"})
	}
	if err := verifyMinisign(req.EndpointsJSON, signature, req.PublicKey); err != nil {
		return encode(applyDiscoveredResult{OK: false, Error: err.Error()})
	}
	if err := rejectForbiddenDiscoveryKeys([]byte(req.EndpointsJSON)); err != nil {
		return encode(applyDiscoveredResult{OK: false, Error: err.Error()})
	}
	var b discoveredBundle
	if err := json.Unmarshal([]byte(req.EndpointsJSON), &b); err != nil {
		return encode(applyDiscoveredResult{OK: false, Error: "parse endpoints json: " + err.Error()})
	}
	now, err := discoveryNow(req.Now)
	if err != nil {
		return encode(applyDiscoveredResult{OK: false, Error: err.Error()})
	}
	if err := validateDiscoveredBundle(b, req.MaxSeenSeq, now); err != nil {
		return encode(applyDiscoveredResult{OK: false, Error: err.Error()})
	}
	selected := "none"
	if len(b.Endpoints.AWG) > 0 {
		sort.SliceStable(b.Endpoints.AWG, func(i, j int) bool { return b.Endpoints.AWG[i].Priority < b.Endpoints.AWG[j].Priority })
		selected = "awg"
	} else if len(b.Endpoints.Reality) > 0 {
		sort.SliceStable(b.Endpoints.Reality, func(i, j int) bool { return b.Endpoints.Reality[i].Priority < b.Endpoints.Reality[j].Priority })
		selected = "reality"
	}
	return encode(applyDiscoveredResult{OK: true, Seq: b.Seq, Selected: selected})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func validateDiscoveredBundle(bundle discoveredBundle, maxSeenSeq int64, now time.Time) error {
	if bundle.Schema != rendezvousSchema {
		return fmt.Errorf("unsupported rendezvous schema: %d", bundle.Schema)
	}
	if bundle.Namespace != rendezvousNamespace {
		return fmt.Errorf("invalid rendezvous namespace: %q", bundle.Namespace)
	}
	if bundle.Seq < maxSeenSeq {
		return fmt.Errorf("rendezvous rollback: seq=%d max_seen_seq=%d", bundle.Seq, maxSeenSeq)
	}
	issuedAt, err := time.Parse(time.RFC3339, bundle.IssuedAt)
	if err != nil {
		return fmt.Errorf("issued_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, bundle.ExpiresAt)
	if err != nil {
		return fmt.Errorf("expires_at: %w", err)
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

func encode(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return `{"ok":false,"error":"marshal result"}`
	}
	return string(raw)
}
