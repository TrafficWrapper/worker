package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetricsHandlerExportsAWGPeerMetrics(t *testing.T) {
	baseSocket := startMetricsUAPIServer(t, []string{
		"public_key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"allowed_ip=10.13.13.2/32",
		"endpoint=198.51.100.10:54321",
		"persistent_keepalive_interval=0",
		"rx_bytes=123",
		"tx_bytes=456",
		"last_handshake_time_sec=1710000000",
		"errno=0",
		"",
		"",
	})
	nextSocket := startMetricsUAPIServer(t, []string{
		"public_key=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
		"allowed_ip=10.44.0.2/32",
		"persistent_keepalive_interval=17",
		"rx_bytes=7",
		"tx_bytes=8",
		"last_handshake_time_sec=1710000001",
		"errno=0",
		"",
		"",
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	quotaBlocksTotal.Store(0)
	awgPeerPolicyDriftTotal.Store(3)
	defer awgPeerPolicyDriftTotal.Store(0)
	metricsHandler(envConfig{AWGProfiles: []awgInboundProfile{
		{Name: "awg", Interface: "awg1", UAPISocket: baseSocket},
		{Name: "next", Interface: "awg2", UAPISocket: nextSocket},
	}}, time.Now().Add(-time.Minute))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`awg_peer_policy_drift_total 3`,
		`tw_worker_awg_interface_up{interface="awg1"} 1`,
		`tw_worker_awg_peer_count{interface="awg1"} 1`,
		`tw_worker_quota_blocks_total{interface="awg1"} 0`,
		`awg_peer_rx_bytes{interface="awg1",peer="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",allowed_ip="10.13.13.2/32",endpoint="198.51.100.10:54321"} 123`,
		`awg_peer_tx_bytes{interface="awg1",peer="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",allowed_ip="10.13.13.2/32",endpoint="198.51.100.10:54321"} 456`,
		`awg_peer_persistent_keepalive_seconds{interface="awg1",peer="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",allowed_ip="10.13.13.2/32",endpoint="198.51.100.10:54321"} 0`,
		`awg_peer_last_handshake_time_seconds{interface="awg1",peer="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",allowed_ip="10.13.13.2/32",endpoint="198.51.100.10:54321"} 1710000000`,
		`tw_worker_awg_interface_up{interface="awg2"} 1`,
		`awg_peer_persistent_keepalive_seconds{interface="awg2",peer="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",allowed_ip="10.44.0.2/32",endpoint=""} 17`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing metric %q in:\n%s", want, body)
		}
	}
}

func TestCollectAWGProfilePeerSnapshotsIncludesEveryProfile(t *testing.T) {
	baseSocket := startMetricsUAPIServer(t, []string{
		"public_key=" + strings.Repeat("01", 32),
		"persistent_keepalive_interval=0",
		"allowed_ip=10.13.13.2/32",
		"errno=0",
		"",
		"",
	})
	nextSocket := startMetricsUAPIServer(t, []string{
		"public_key=" + strings.Repeat("02", 32),
		"persistent_keepalive_interval=17",
		"allowed_ip=10.44.0.2/32",
		"errno=0",
		"",
		"",
	})
	snapshots := collectAWGProfilePeerSnapshots(envConfig{AWGProfiles: []awgInboundProfile{
		{Name: "awg", Interface: "awg1", UAPISocket: baseSocket},
		{Name: "next", Interface: "awg2", UAPISocket: nextSocket},
	}})
	if len(snapshots) != 2 {
		t.Fatalf("snapshots=%d want 2: %+v", len(snapshots), snapshots)
	}
	if snapshots[0].Profile != "awg" || len(snapshots[0].Peers) != 1 || snapshots[0].Peers[0].PersistentKeepalive != 0 {
		t.Fatalf("bad base snapshot: %+v", snapshots[0])
	}
	if snapshots[1].Profile != "next" || len(snapshots[1].Peers) != 1 || snapshots[1].Peers[0].PersistentKeepalive != 17 {
		t.Fatalf("bad next snapshot: %+v", snapshots[1])
	}
}

func TestWriteAWGMetricsScrubsPeerLabelsWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	peer := awgPeerConfig{
		PublicKeyHex:     "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		AllowedIPs:       []string{"10.13.13.2/32"},
		Endpoint:         "198.51.100.10:54321",
		RxBytes:          123,
		TxBytes:          456,
		LastHandshakeSec: 1710000000,
	}
	writeAWGMetricsWithOptions(&buf, "awg1", time.Now(), []awgPeerConfig{peer}, metricsOptions{
		ScrubPeerLabels: true,
		Salt:            "secret-salt-a",
	})
	body := buf.String()
	if strings.Contains(body, peer.PublicKeyHex) {
		t.Fatalf("raw peer leaked in scrubbed metrics:\n%s", body)
	}
	if strings.Contains(body, "endpoint=") || strings.Contains(body, peer.Endpoint) {
		t.Fatalf("endpoint leaked in scrubbed metrics:\n%s", body)
	}
	if strings.Contains(body, "allowed_ip=") || strings.Contains(body, "10.13.13.2/32") {
		t.Fatalf("allowed_ip leaked in scrubbed metrics:\n%s", body)
	}
	if !strings.Contains(body, `peer="peer_`) {
		t.Fatalf("scrubbed peer label missing:\n%s", body)
	}
}

func TestScrubbedPeerLabelUsesRotatableSecretSalt(t *testing.T) {
	peer := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	first := scrubbedPeerLabel("secret-a", peer)
	if first != scrubbedPeerLabel("secret-a", peer) {
		t.Fatalf("scrubbed label is not stable for fixed salt")
	}
	if first == scrubbedPeerLabel("secret-b", peer) {
		t.Fatalf("scrubbed label did not change after salt rotation")
	}
	if first == scrubbedPeerLabel("/worker-state", peer) {
		t.Fatalf("test secret unexpectedly matched public state-dir salt")
	}
}

func TestLoadMetricsScrubSaltPersistsSecretFileAndEnvOverride(t *testing.T) {
	stateDir := t.TempDir()
	first, err := loadMetricsScrubSalt(stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first == stateDir {
		t.Fatalf("unexpected generated salt %q for stateDir %q", first, stateDir)
	}
	info, err := os.Stat(filepath.Join(stateDir, metricsScrubSaltFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("metrics salt file mode=%#o, want 0600", got)
	}
	second, err := loadMetricsScrubSalt(stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("salt was not persisted: first=%q second=%q", first, second)
	}
	override, err := loadMetricsScrubSalt(stateDir, " override-secret ")
	if err != nil {
		t.Fatal(err)
	}
	if override != "override-secret" {
		t.Fatalf("env override=%q, want override-secret", override)
	}
}

func startMetricsUAPIServer(t *testing.T, response []string) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "awg.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		_, _ = io.WriteString(conn, strings.Join(response, "\n"))
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return socketPath
}
