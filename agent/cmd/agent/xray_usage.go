package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	if strings.TrimSpace(cfg.XrayContainer) == "" {
		return nil, errors.New("XRAY_CONTAINER_NAME is not configured")
	}
	raw, err := queryXrayStatsViaDocker(cfg)
	if err != nil {
		return nil, err
	}
	return buildRealityUsageReports(devices, raw)
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

func queryXrayStatsViaDocker(cfg envConfig) ([]byte, error) {
	client := dockerUnixClient(cfg.DockerSocket, xrayStatsQueryTimeout)
	command := []string{
		"/usr/local/bin/xray",
		"api",
		"statsquery",
		fmt.Sprintf("--server=127.0.0.1:%d", xrayAPIInPort),
		"-pattern",
		"user>>>",
		"-reset=false",
	}
	for _, candidate := range dockerContainerNameCandidates(cfg.XrayContainer) {
		stdout, err := dockerExec(client, candidate, command)
		if err == nil {
			return stdout, nil
		}
		if !errors.Is(err, errDockerContainerNotFound) {
			return nil, err
		}
	}
	discovered, err := discoverDockerContainerByComposeService(client, "xray")
	if err != nil {
		return nil, fmt.Errorf("discover xray container: %w", err)
	}
	if discovered == "" {
		return nil, fmt.Errorf("docker container %q not found", cfg.XrayContainer)
	}
	return dockerExec(client, discovered, command)
}

func dockerUnixClient(socketPath string, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

func dockerExec(client *http.Client, container string, command []string) ([]byte, error) {
	createBody, err := json.Marshal(map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          command,
	})
	if err != nil {
		return nil, err
	}
	createURL := "http://docker/containers/" + url.PathEscape(container) + "/exec"
	createResp, err := dockerJSONRequest(client, http.MethodPost, createURL, createBody)
	if err != nil {
		return nil, err
	}
	if createResp.StatusCode == http.StatusNotFound {
		createResp.Body.Close()
		return nil, errDockerContainerNotFound
	}
	if createResp.StatusCode != http.StatusCreated {
		return nil, dockerHTTPError("create exec", createResp)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(io.LimitReader(createResp.Body, 64<<10)).Decode(&created); err != nil {
		createResp.Body.Close()
		return nil, fmt.Errorf("decode docker exec create: %w", err)
	}
	createResp.Body.Close()
	if strings.TrimSpace(created.ID) == "" {
		return nil, errors.New("docker exec create returned empty id")
	}
	startBody := []byte(`{"Detach":false,"Tty":false}`)
	startURL := "http://docker/exec/" + url.PathEscape(created.ID) + "/start"
	startResp, err := dockerJSONRequest(client, http.MethodPost, startURL, startBody)
	if err != nil {
		return nil, err
	}
	if startResp.StatusCode != http.StatusOK {
		return nil, dockerHTTPError("start exec", startResp)
	}
	raw, err := io.ReadAll(io.LimitReader(startResp.Body, xrayStatsOutputLimit+1))
	startResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read docker exec output: %w", err)
	}
	if len(raw) > xrayStatsOutputLimit {
		return nil, errors.New("docker exec output exceeds limit")
	}
	stdout, stderr, err := decodeDockerRawStream(raw)
	if err != nil {
		return nil, err
	}
	inspectURL := "http://docker/exec/" + url.PathEscape(created.ID) + "/json"
	inspectResp, err := dockerJSONRequest(client, http.MethodGet, inspectURL, nil)
	if err != nil {
		return nil, err
	}
	if inspectResp.StatusCode != http.StatusOK {
		return nil, dockerHTTPError("inspect exec", inspectResp)
	}
	var inspected struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	}
	if err := json.NewDecoder(io.LimitReader(inspectResp.Body, 64<<10)).Decode(&inspected); err != nil {
		inspectResp.Body.Close()
		return nil, fmt.Errorf("decode docker exec inspect: %w", err)
	}
	inspectResp.Body.Close()
	if inspected.Running {
		return nil, errors.New("docker exec still running after output closed")
	}
	if inspected.ExitCode != 0 {
		return nil, fmt.Errorf("xray statsquery exit=%d: %s", inspected.ExitCode, strings.TrimSpace(string(stderr)))
	}
	return stdout, nil
}

func dockerJSONRequest(client *http.Client, method, endpoint string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return client.Do(req)
}

func dockerHTTPError(action string, resp *http.Response) error {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("docker %s http %d: %s", action, resp.StatusCode, strings.TrimSpace(string(body)))
}

func decodeDockerRawStream(raw []byte) ([]byte, []byte, error) {
	if len(raw) < 8 || (raw[0] != 1 && raw[0] != 2) || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
		return raw, nil, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	for len(raw) > 0 {
		if len(raw) < 8 {
			return nil, nil, errors.New("truncated docker stream header")
		}
		stream := raw[0]
		length := int(binary.BigEndian.Uint32(raw[4:8]))
		raw = raw[8:]
		if length < 0 || length > len(raw) {
			return nil, nil, errors.New("truncated docker stream payload")
		}
		switch stream {
		case 1:
			stdout.Write(raw[:length])
		case 2:
			stderr.Write(raw[:length])
		default:
			return nil, nil, fmt.Errorf("unsupported docker stream %d", stream)
		}
		raw = raw[length:]
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}
