package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	realityUsageSource    = "reality"
	xrayStatsOutputLimit  = 4 << 20
	xrayStatsQueryTimeout = 10 * time.Second
)

type xrayStatsQueryResponse struct {
	Stats []xrayStat `json:"stat"`
}

type xrayStat struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

func collectRealityUsageReports(cfg envConfig, devices []approvedDevice) ([]orchUsageReport, error) {
	if len(devices) == 0 {
		return nil, nil
	}
	raw, err := queryXrayStats(cfg)
	if err != nil {
		return nil, err
	}
	deltas, err := buildRealityUsageReports(devices, raw)
	if err != nil {
		return nil, err
	}
	state := loadUsageState(realityUsageStatePath(cfg.StateDir))
	reports := accumulateRealityUsage(deltas, state, time.Now().UTC())
	if err := saveUsageState(realityUsageStatePath(cfg.StateDir), state); err != nil {
		slog.Warn("reality usage state save failed", "err", err)
	}
	return reports, nil
}

// accumulateRealityUsage adds the per-query deltas to the persisted totals and
// reports the totals, matching the cumulative semantics of AWG usage reports.
func accumulateRealityUsage(deltas []orchUsageReport, state usageState, now time.Time) []orchUsageReport {
	reports := make([]orchUsageReport, 0, len(deltas))
	for _, delta := range deltas {
		key := realityUsageSource + ":" + delta.DeviceID
		snap := state[key]
		snap.RxBytes = addUint64Saturating(snap.RxBytes, delta.RxBytes)
		snap.TxBytes = addUint64Saturating(snap.TxBytes, delta.TxBytes)
		snap.UpdatedAt = now
		state[key] = snap
		delta.RxBytes = snap.RxBytes
		delta.TxBytes = snap.TxBytes
		reports = append(reports, delta)
	}
	state.prune(now)
	return reports
}

func realityUsageStatePath(stateDir string) string {
	return filepath.Join(stateDir, "xray", "usage.json")
}

func buildRealityUsageReports(devices []approvedDevice, raw []byte) ([]orchUsageReport, error) {
	var response xrayStatsQueryResponse
	if err := json.Unmarshal(extractJSONObject(raw), &response); err != nil {
		return nil, fmt.Errorf("parse xray stats: %w", err)
	}
	usage := make(map[string]*orchUsageReport, len(devices))
	for _, device := range devices {
		deviceID := strings.TrimSpace(device.DeviceID)
		if device.Status != "approved" || deviceID == "" || strings.TrimSpace(device.RealityUUID) == "" {
			continue
		}
		usage[deviceID] = &orchUsageReport{DeviceID: deviceID, Source: realityUsageSource}
	}
	for _, stat := range response.Stats {
		deviceID, direction, ok := parseXrayUserStatName(stat.Name)
		if !ok {
			continue
		}
		report := usage[deviceID]
		if report == nil {
			continue
		}
		value, err := parseXrayStatValue(stat.Value)
		if err != nil {
			return nil, fmt.Errorf("parse xray stat %q: %w", stat.Name, err)
		}
		switch direction {
		case "uplink":
			report.RxBytes = addUint64Saturating(report.RxBytes, value)
		case "downlink":
			report.TxBytes = addUint64Saturating(report.TxBytes, value)
		}
	}
	ids := make([]string, 0, len(usage))
	for id := range usage {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	reports := make([]orchUsageReport, 0, len(ids))
	for _, id := range ids {
		reports = append(reports, *usage[id])
	}
	return reports, nil
}

func parseXrayUserStatName(name string) (string, string, bool) {
	const prefix = "user>>>"
	if !strings.HasPrefix(name, prefix) {
		return "", "", false
	}
	for _, direction := range []string{"uplink", "downlink"} {
		suffix := ">>>traffic>>>" + direction
		if strings.HasSuffix(name, suffix) {
			deviceID := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
			if strings.TrimSpace(deviceID) == "" {
				return "", "", false
			}
			return deviceID, direction, true
		}
	}
	return "", "", false
}

func parseXrayStatValue(raw json.RawMessage) (uint64, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strconv.ParseUint(text, 10, 64)
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func extractJSONObject(raw []byte) []byte {
	start := bytes.IndexByte(raw, '{')
	end := bytes.LastIndexByte(raw, '}')
	if start >= 0 && end >= start {
		return raw[start : end+1]
	}
	return raw
}

func addUint64Saturating(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

// queryXrayStats reads and resets the per-user counters, so every call
// returns the traffic since the previous call and an Xray restart in between
// cannot make the reported totals go backwards.
func queryXrayStats(cfg envConfig) ([]byte, error) {
	return runXrayAPI(cfg, xrayStatsQueryTimeout, "statsquery", "-pattern", "user>>>", "-reset=true")
}

// runXrayAPI runs the bundled xray CLI against the API socket shared with
// the Xray container. It is a variable so tests can replace it.
var runXrayAPI = func(cfg envConfig, timeout time.Duration, subcommand string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"api", subcommand, "--server=unix://" + cfg.XrayAPISocket}, args...)
	cmd := exec.CommandContext(ctx, cfg.XrayBinary, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		xrayAPIErrorsTotal.Add(1)
		return nil, fmt.Errorf("xray api %s: %w: %s", subcommand, err, strings.TrimSpace(stderr.String()+" "+stdout.String()))
	}
	if stdout.Len() > xrayStatsOutputLimit {
		return nil, errors.New("xray api output exceeds limit")
	}
	return stdout.Bytes(), nil
}
