package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aead.dev/minisign"
)

const orchStatusRevoked = "revoked"

// desiredState is what the applied worker config asks this worker to serve.
// Every render, reconcile and usage path reads devices through it, so the
// protocol switches and a revocation apply everywhere at once.
type desiredState struct {
	devices        []approvedDevice
	realityEnabled bool
	awgEnabled     bool
	// input counts the approved entries in the bundle, rejected those that
	// failed validation.
	input    int
	rejected int
	// signed is set when the cached bundle's signature was verified, so an
	// empty or switched-off set in it is a real instruction.
	signed  bool
	revoked bool
}

type workerConfigDocument struct {
	Schema       json.RawMessage `json:"schema,omitempty"`
	WorkerID     string          `json:"worker_id,omitempty"`
	DesiredState struct {
		ApprovedDevices []approvedDevice   `json:"approved_devices"`
		Reality         desiredProtocolRaw `json:"reality"`
		AWG             desiredProtocolRaw `json:"awg"`
	} `json:"desired_state"`
}

type desiredProtocolRaw struct {
	// Enabled is absent in bundles from older orchestrators, which means on.
	Enabled *bool `json:"enabled"`
}

func (p desiredProtocolRaw) enabled() bool {
	return p.Enabled == nil || *p.Enabled
}

func parseDesiredState(raw string) (desiredState, error) {
	var doc workerConfigDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return desiredState{}, err
	}
	ds := desiredState{
		devices:        make([]approvedDevice, 0, len(doc.DesiredState.ApprovedDevices)),
		realityEnabled: doc.DesiredState.Reality.enabled(),
		awgEnabled:     doc.DesiredState.AWG.enabled(),
	}
	for _, device := range doc.DesiredState.ApprovedDevices {
		if device.Status != "approved" {
			continue
		}
		ds.input++
		normalized, err := normalizeApprovedDevice(device)
		if err != nil {
			// One malformed device must not block every other device on the
			// worker, so it is skipped instead of failing the whole bundle.
			slog.Warn("approved device skipped", "device_id", sanitizeLogValue(device.DeviceID), "err", err)
			ds.rejected++
			continue
		}
		ds.devices = append(ds.devices, normalized)
	}
	return ds, nil
}

// checkWorkerConfigIdentity rejects a bundle signed for another worker or in
// an unknown schema. Older bundles without these fields are accepted.
func checkWorkerConfigIdentity(raw, workerID string) error {
	var doc workerConfigDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return err
	}
	if doc.WorkerID != "" && workerID != "" && doc.WorkerID != workerID {
		return fmt.Errorf("worker config is for worker %q, not %q", sanitizeLogValue(doc.WorkerID), sanitizeLogValue(workerID))
	}
	if len(doc.Schema) > 0 && string(doc.Schema) != "null" {
		var schema int
		if err := json.Unmarshal(doc.Schema, &schema); err != nil || schema != 1 {
			return fmt.Errorf("unsupported worker config schema %s", strings.TrimSpace(string(doc.Schema)))
		}
	}
	return nil
}

// maxRejectedShare is the share of invalid devices above which a bundle is
// treated as broken rather than applied without them.
const maxRejectedShare = 0.5

// checkRejections refuses to apply a non-empty device list that lost all or
// most of its entries to validation, since that would wipe working users.
func (d desiredState) checkRejections() error {
	if d.input == 0 || d.rejected == 0 {
		return nil
	}
	if d.rejected == d.input || float64(d.rejected) > maxRejectedShare*float64(d.input) {
		return fmt.Errorf("refusing worker config: %d of %d approved devices are invalid", d.rejected, d.input)
	}
	return nil
}

func (d desiredState) realityDevices(now time.Time) []approvedDevice {
	if d.revoked || !d.realityEnabled {
		return nil
	}
	return filterUnexpiredApprovedDevices(d.devices, now)
}

func (d desiredState) awgDevices(now time.Time) []approvedDevice {
	if d.revoked || !d.awgEnabled {
		return nil
	}
	return filterUnexpiredApprovedDevices(d.devices, now)
}

// realityIntentionallyEmpty is awgIntentionallyEmpty for REALITY users.
func (d desiredState) realityIntentionallyEmpty() bool {
	return d.revoked || (d.signed && (!d.realityEnabled || d.input == 0))
}

// awgIntentionallyEmpty tells the anti-wipe guards that an empty AWG set is
// what the orchestrator asked for rather than a lost or damaged cache.
func (d desiredState) awgIntentionallyEmpty() bool {
	return d.revoked || (d.signed && (!d.awgEnabled || d.input == 0))
}

// loadCachedDesiredState reads the applied worker config kept after the last
// successful apply. A revoked worker serves nothing regardless of the cache.
func loadCachedDesiredState(stateDir string) (desiredState, error) {
	state := loadOrchState(stateDir)
	if state.Status == orchStatusRevoked {
		return desiredState{revoked: true}, nil
	}
	path := filepath.Join(stateDir, "orch", "worker-config.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return desiredState{}, fmt.Errorf("read cached worker config: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return desiredState{}, errors.New("cached worker config is empty")
	}
	ds, err := parseDesiredState(string(raw))
	if err != nil {
		return desiredState{}, fmt.Errorf("parse cached worker config: %w", err)
	}
	ds.signed = cachedWorkerConfigSigned(stateDir, state.SignerPublicKey, raw)
	return ds, nil
}

// cachedWorkerConfigSigned verifies the cached config against the signature
// saved next to it with the pinned signer key.
func cachedWorkerConfigSigned(stateDir, signerPublicKey string, raw []byte) bool {
	if signerPublicKey == "" {
		return false
	}
	sig, err := os.ReadFile(filepath.Join(stateDir, "orch", "worker-config.minisig"))
	if err != nil {
		return false
	}
	var pub minisign.PublicKey
	if err := pub.UnmarshalText([]byte(signerPublicKey)); err != nil {
		return false
	}
	// The cache holds the signed text plus a trailing newline.
	return minisign.Verify(pub, []byte(strings.TrimSuffix(string(raw), "\n")), sig)
}

// cachedDesiredState is loadCachedDesiredState for paths that fall back to
// serving nothing when the cache is unusable.
func cachedDesiredState(stateDir string) desiredState {
	ds, err := loadCachedDesiredState(stateDir)
	if err != nil {
		slog.Warn("cached approved_devices ignored", "err", err)
		return desiredState{realityEnabled: true, awgEnabled: true}
	}
	return ds
}
