package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// usageStateRetention bounds usage state files: entries for devices or keys
// that have not been seen for this long are dropped.
const usageStateRetention = 90 * 24 * time.Hour

type usageState map[string]usageSnapshot

type awgUsageState = usageState

type usageSnapshot struct {
	RxBytes     uint64    `json:"rx_bytes,omitempty"`
	TxBytes     uint64    `json:"tx_bytes,omitempty"`
	LastRxBytes uint64    `json:"last_rx_bytes,omitempty"`
	LastTxBytes uint64    `json:"last_tx_bytes,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

func collectAWGUsageReports(cfg envConfig, devices []approvedDevice) ([]orchUsageReport, error) {
	if len(devices) == 0 {
		return nil, nil
	}
	allPeers := []awgPeerConfig{}
	for _, profile := range awgProfiles(cfg) {
		if profile.UAPISocket == "" {
			continue
		}
		peers, err := listAWGPeerConfigs(profile.UAPISocket)
		if err != nil {
			return nil, err
		}
		allPeers = append(allPeers, peers...)
	}
	if len(allPeers) == 0 {
		return nil, nil
	}
	state := loadAWGUsageState(cfg.StateDir)
	now := time.Now().UTC()
	reports, next := buildAWGUsageReports(devices, allPeers, state, now)
	next.prune(now)
	if err := saveAWGUsageState(cfg.StateDir, next); err != nil {
		log.Printf("awg usage state save failed: %v", err)
	}
	return reports, nil
}

func buildAWGUsageReports(devices []approvedDevice, peers []awgPeerConfig, previous awgUsageState, now time.Time) ([]orchUsageReport, awgUsageState) {
	peerByHex := make(map[string][]awgPeerConfig, len(peers))
	for _, peer := range peers {
		peerByHex[peer.PublicKeyHex] = append(peerByHex[peer.PublicKeyHex], peer)
	}
	next := make(awgUsageState, len(previous)+len(devices))
	for key, value := range previous {
		next[key] = value
	}
	reports := make([]orchUsageReport, 0, len(devices))
	for _, device := range devices {
		deviceID := device.DeviceID
		if deviceID == "" && device.AWGPublicKey != "" {
			deviceID = device.AWGPublicKey
		}
		report, ok := buildAWGUsageReportForDevice(device, deviceID, peerByHex, next, now)
		if !ok {
			continue
		}
		reports = append(reports, report)
	}
	return reports, next
}

func buildAWGUsageReportForDevice(device approvedDevice, deviceID string, peerByHex map[string][]awgPeerConfig, next awgUsageState, now time.Time) (orchUsageReport, bool) {
	candidates := []approvedDeviceAWGProfile{}
	seenCandidate := map[string]struct{}{}
	if strings.TrimSpace(device.AWGPublicKey) != "" {
		key := strings.TrimSpace(device.AWGPublicKey)
		candidates = append(candidates, approvedDeviceAWGProfile{AWGPublicKey: key})
		seenCandidate[key] = struct{}{}
	}
	for _, creds := range device.AWGProfiles {
		key := strings.TrimSpace(creds.AWGPublicKey)
		if key == "" {
			continue
		}
		if _, ok := seenCandidate[key]; ok {
			continue
		}
		creds.AWGPublicKey = key
		candidates = append(candidates, creds)
		seenCandidate[key] = struct{}{}
	}
	if deviceID == "" && len(candidates) > 0 {
		deviceID = candidates[0].AWGPublicKey
	}
	if deviceID == "" {
		return orchUsageReport{}, false
	}
	matched := false
	reportKey := ""
	totalRx := uint64(0)
	totalTx := uint64(0)
	for _, creds := range candidates {
		pubHex, err := base64KeyToHex(creds.AWGPublicKey)
		if err != nil {
			log.Printf("awg usage skips device %s profile key: %v", device.DeviceID, err)
			continue
		}
		peers := peerByHex[pubHex]
		if len(peers) == 0 {
			continue
		}
		for i, peer := range peers {
			matched = true
			if reportKey == "" {
				reportKey = creds.AWGPublicKey
			}
			stateKey := fmt.Sprintf("%s:%s:%d", deviceID, creds.AWGPublicKey, i)
			snap := next[stateKey]
			snap.RxBytes += counterDelta(snap.LastRxBytes, peer.RxBytes)
			snap.TxBytes += counterDelta(snap.LastTxBytes, peer.TxBytes)
			snap.LastRxBytes = peer.RxBytes
			snap.LastTxBytes = peer.TxBytes
			snap.UpdatedAt = now
			next[stateKey] = snap
			totalRx += snap.RxBytes
			totalTx += snap.TxBytes
		}
	}
	if !matched {
		return orchUsageReport{}, false
	}
	return orchUsageReport{
		DeviceID:     device.DeviceID,
		AWGPublicKey: reportKey,
		RxBytes:      totalRx,
		TxBytes:      totalTx,
	}, true
}

func counterDelta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func awgUsageStatePath(stateDir string) string {
	return filepath.Join(stateDir, "awg", "usage.json")
}

func (state usageState) prune(now time.Time) {
	for key, snap := range state {
		if !snap.UpdatedAt.IsZero() && now.Sub(snap.UpdatedAt) > usageStateRetention {
			delete(state, key)
		}
	}
}

func loadAWGUsageState(stateDir string) awgUsageState {
	return loadUsageState(awgUsageStatePath(stateDir))
}

func saveAWGUsageState(stateDir string, state awgUsageState) error {
	return saveUsageState(awgUsageStatePath(stateDir), state)
}

func loadUsageState(path string) usageState {
	raw, err := os.ReadFile(path)
	if err != nil {
		return usageState{}
	}
	var state usageState
	if err := json.Unmarshal(raw, &state); err != nil {
		log.Printf("usage state %s ignored: %v", path, err)
		return usageState{}
	}
	if state == nil {
		return usageState{}
	}
	return state
}

func saveUsageState(path string, state usageState) error {
	return writeJSONFile(path, state, 0o600)
}
