package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

type awgUsageState map[string]awgUsageSnapshot

type awgUsageSnapshot struct {
	RxBytes     uint64    `json:"rx_bytes,omitempty"`
	TxBytes     uint64    `json:"tx_bytes,omitempty"`
	LastRxBytes uint64    `json:"last_rx_bytes,omitempty"`
	LastTxBytes uint64    `json:"last_tx_bytes,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

func collectAWGUsageReports(cfg envConfig, devices []approvedDevice) ([]orchUsageReport, error) {
	if cfg.AWGUAPISocket == "" || len(devices) == 0 {
		return nil, nil
	}
	peers, err := listAWGPeerConfigs(cfg.AWGUAPISocket)
	if err != nil {
		return nil, err
	}
	state := loadAWGUsageState(cfg.StateDir)
	reports, next := buildAWGUsageReports(devices, peers, state, time.Now().UTC())
	if err := saveAWGUsageState(cfg.StateDir, next); err != nil {
		log.Printf("awg usage state save failed: %v", err)
	}
	return reports, nil
}

func buildAWGUsageReports(devices []approvedDevice, peers []awgPeerConfig, previous awgUsageState, now time.Time) ([]orchUsageReport, awgUsageState) {
	peerByHex := make(map[string]awgPeerConfig, len(peers))
	for _, peer := range peers {
		peerByHex[peer.PublicKeyHex] = peer
	}
	next := make(awgUsageState, len(previous)+len(devices))
	for key, value := range previous {
		next[key] = value
	}
	reports := make([]orchUsageReport, 0, len(devices))
	for _, device := range devices {
		deviceID := device.DeviceID
		if deviceID == "" {
			deviceID = device.AWGPublicKey
		}
		pubHex, err := base64KeyToHex(device.AWGPublicKey)
		if err != nil {
			log.Printf("awg usage skips device %s: bad public key: %v", device.DeviceID, err)
			continue
		}
		peer, ok := peerByHex[pubHex]
		if !ok {
			continue
		}
		snap := next[deviceID]
		snap.RxBytes += counterDelta(snap.LastRxBytes, peer.RxBytes)
		snap.TxBytes += counterDelta(snap.LastTxBytes, peer.TxBytes)
		snap.LastRxBytes = peer.RxBytes
		snap.LastTxBytes = peer.TxBytes
		snap.UpdatedAt = now
		next[deviceID] = snap
		reports = append(reports, orchUsageReport{
			DeviceID:     device.DeviceID,
			AWGPublicKey: device.AWGPublicKey,
			RxBytes:      snap.RxBytes,
			TxBytes:      snap.TxBytes,
		})
	}
	return reports, next
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

func loadAWGUsageState(stateDir string) awgUsageState {
	raw, err := os.ReadFile(awgUsageStatePath(stateDir))
	if err != nil {
		return awgUsageState{}
	}
	var state awgUsageState
	if err := json.Unmarshal(raw, &state); err != nil {
		log.Printf("awg usage state ignored: %v", err)
		return awgUsageState{}
	}
	if state == nil {
		return awgUsageState{}
	}
	return state
}

func saveAWGUsageState(stateDir string, state awgUsageState) error {
	return writeJSONFile(awgUsageStatePath(stateDir), state, 0o600)
}
