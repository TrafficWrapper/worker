package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

var quotaBlocksTotal atomic.Uint64

func metricsHandler(cfg envConfig, startedAt time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", metricsContentType)
		peers, err := listAWGPeerConfigs(cfg.AWGUAPISocket)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "tw_worker_awg_interface_up{interface=%q} 0\n", awgMetricsInterface())
			_, _ = fmt.Fprintf(w, "tw_worker_awg_scrape_error{interface=%q,error=%q} 1\n", awgMetricsInterface(), err.Error())
			return
		}
		writeAWGMetricsWithOptions(w, awgMetricsInterface(), startedAt, peers, metricsOptions{
			ScrubPeerLabels: cfg.MetricsScrubPeerLabels,
			Salt:            cfg.StateDir,
		})
	}
}

func writeAWGMetrics(w io.Writer, iface string, startedAt time.Time, peers []awgPeerConfig) {
	writeAWGMetricsWithOptions(w, iface, startedAt, peers, metricsOptions{})
}

type metricsOptions struct {
	ScrubPeerLabels bool
	Salt            string
}

func writeAWGMetricsWithOptions(w io.Writer, iface string, startedAt time.Time, peers []awgPeerConfig, opts metricsOptions) {
	_, _ = fmt.Fprintf(w, "tw_worker_awg_interface_up{interface=%q} 1\n", iface)
	_, _ = fmt.Fprintf(w, "tw_worker_awg_peer_count{interface=%q} %d\n", iface, len(peers))
	_, _ = fmt.Fprintf(w, "tw_worker_awg_metrics_uptime_seconds{interface=%q} %.0f\n", iface, time.Since(startedAt).Seconds())
	_, _ = fmt.Fprintf(w, "tw_worker_quota_blocks_total{interface=%q} %d\n", iface, quotaBlocksTotal.Load())
	for _, peer := range peers {
		allowedIPs := append([]string(nil), peer.AllowedIPs...)
		sort.Strings(allowedIPs)
		peerLabel := peer.PublicKeyHex
		if opts.ScrubPeerLabels {
			peerLabel = scrubbedPeerLabel(opts.Salt, peer.PublicKeyHex)
		}
		labels := fmt.Sprintf("interface=%q,peer=%q", iface, peerLabel)
		if !opts.ScrubPeerLabels {
			labels += fmt.Sprintf(",allowed_ip=%q,endpoint=%q", strings.Join(allowedIPs, ","), peer.Endpoint)
		}
		_, _ = fmt.Fprintf(w, "awg_peer_rx_bytes{%s} %d\n", labels, peer.RxBytes)
		_, _ = fmt.Fprintf(w, "awg_peer_tx_bytes{%s} %d\n", labels, peer.TxBytes)
		_, _ = fmt.Fprintf(w, "awg_peer_last_handshake_time_seconds{%s} %d\n", labels, peer.LastHandshakeSec)
	}
}

func scrubbedPeerLabel(salt, peerHex string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(salt) + "\x00" + strings.TrimSpace(peerHex)))
	return "peer_" + hex.EncodeToString(sum[:8])
}

func awgMetricsInterface() string {
	return "awg1"
}
