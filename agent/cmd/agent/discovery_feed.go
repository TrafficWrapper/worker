package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

// maxDiscoveryFeedBytes bounds the feed the worker republishes.
const maxDiscoveryFeedBytes = 256 << 10

type orchDiscoveryBundle struct {
	EndpointsJSON        string `json:"endpoints_json"`
	EndpointsJSONMinisig string `json:"endpoints_json_minisig"`
}

// publishDiscoveryBundle serves the orchestrator's signed discovery feed as
// /tw/endpoints.json(.minisig), so clients refresh discovery through the
// tunnel instead of going to the orchestrator directly. Clients verify the
// signature; the worker only checks that both parts are present and sane.
func publishDiscoveryBundle(stateDir string, bundle orchDiscoveryBundle) error {
	feed := strings.TrimSpace(bundle.EndpointsJSON)
	sig := strings.TrimSpace(bundle.EndpointsJSONMinisig)
	if feed == "" || sig == "" {
		return errors.New("discovery_bundle without feed or signature")
	}
	if len(feed) > maxDiscoveryFeedBytes || len(sig) > 4096 {
		return errors.New("discovery_bundle too large")
	}
	if !json.Valid([]byte(feed)) {
		return errors.New("discovery feed is not JSON")
	}
	twDir := filepath.Join(stateDir, "distributor", "tw")
	if err := writeFile(filepath.Join(twDir, "endpoints.json"), []byte(feed), 0o644); err != nil {
		return err
	}
	return writeFile(filepath.Join(twDir, "endpoints.json.minisig"), []byte(sig), 0o644)
}
