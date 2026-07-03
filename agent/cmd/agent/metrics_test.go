package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetricsHandlerExportsAWGPeerMetrics(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "awg.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
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
		_, _ = io.WriteString(conn, strings.Join([]string{
			"public_key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			"allowed_ip=10.13.13.2/32",
			"endpoint=198.51.100.10:54321",
			"rx_bytes=123",
			"tx_bytes=456",
			"last_handshake_time_sec=1710000000",
			"errno=0",
			"",
			"",
		}, "\n"))
	}()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	metricsHandler(envConfig{AWGUAPISocket: socketPath}, time.Now().Add(-time.Minute))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`tw_worker_awg_interface_up{interface="awg1"} 1`,
		`tw_worker_awg_peer_count{interface="awg1"} 1`,
		`tw_worker_quota_blocks_total{interface="awg1"} 0`,
		`awg_peer_rx_bytes{interface="awg1",peer="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",allowed_ip="10.13.13.2/32",endpoint="198.51.100.10:54321"} 123`,
		`awg_peer_tx_bytes{interface="awg1",peer="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",allowed_ip="10.13.13.2/32",endpoint="198.51.100.10:54321"} 456`,
		`awg_peer_last_handshake_time_seconds{interface="awg1",peer="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",allowed_ip="10.13.13.2/32",endpoint="198.51.100.10:54321"} 1710000000`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing metric %q in:\n%s", want, body)
		}
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
		Salt:            "/worker-state",
	})
	body := buf.String()
	if strings.Contains(body, peer.PublicKeyHex) {
		t.Fatalf("raw peer leaked in scrubbed metrics:\n%s", body)
	}
	if strings.Contains(body, "endpoint=") || strings.Contains(body, peer.Endpoint) {
		t.Fatalf("endpoint leaked in scrubbed metrics:\n%s", body)
	}
	if !strings.Contains(body, `peer="peer_`) {
		t.Fatalf("scrubbed peer label missing:\n%s", body)
	}
}
