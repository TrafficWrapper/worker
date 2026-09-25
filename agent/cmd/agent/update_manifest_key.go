package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"
)

// updateManifestKey returns the update signing key named by update_pubkey in
// the published client config, which the agent only writes after verifying
// it with the pinned signer key. ok is false when there is no such key (an
// orchestrator that does not send it) or it cannot be read; the manifest is
// then published unchecked, as before, and clients still verify it.
func updateManifestKey(stateDir string) (pub minisign.PublicKey, ok bool) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "distributor", "tw", "config.json"))
	if err != nil {
		return pub, false
	}
	var cfg struct {
		UpdatePubkey string `json:"update_pubkey"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return pub, false
	}
	key := strings.TrimSpace(cfg.UpdatePubkey)
	// Accept a whole minisign .pub file as well as the bare key line.
	if i := strings.LastIndexByte(key, '\n'); i >= 0 {
		key = strings.TrimSpace(key[i+1:])
	}
	if key == "" || pub.UnmarshalText([]byte(key)) != nil {
		return pub, false
	}
	return pub, true
}

// checkUpdateManifestSignature rejects a manifest whose signature does not
// verify with the client config's update key, so the worker never serves a
// release the clients would refuse. The published text is the trimmed
// manifest; the text exactly as received is accepted too, as before.
func checkUpdateManifestSignature(stateDir, manifestJSON, minisig string) error {
	pub, ok := updateManifestKey(stateDir)
	if !ok {
		return nil
	}
	sig := []byte(minisig)
	if minisign.Verify(pub, []byte(strings.TrimSpace(manifestJSON)), sig) || minisign.Verify(pub, []byte(manifestJSON), sig) {
		return nil
	}
	return errors.New("update manifest signature does not verify with update_pubkey")
}
