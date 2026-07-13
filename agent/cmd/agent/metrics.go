package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"
const metricsScrubSaltFile = "metrics_salt"

var (
	quotaBlocksTotal        atomic.Uint64
	awgPeerPolicyDriftTotal atomic.Uint64
)

func metricsHandler(cfg envConfig, startedAt time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", metricsContentType)
		_, _ = fmt.Fprintf(w, "awg_peer_policy_drift_total %d\n", awgPeerPolicyDriftTotal.Load())
		for _, snapshot := range collectAWGProfilePeerSnapshots(cfg) {
			if snapshot.Error != "" {
				_, _ = fmt.Fprintf(w, "tw_worker_awg_interface_up{interface=%q} 0\n", snapshot.Interface)
				_, _ = fmt.Fprintf(w, "tw_worker_awg_scrape_error{interface=%q,error=%q} 1\n", snapshot.Interface, snapshot.Error)
				continue
			}
			writeAWGMetricsWithOptions(w, snapshot.Interface, startedAt, snapshot.Peers, metricsOptions{
				ScrubPeerLabels: cfg.MetricsScrubPeerLabels,
				Salt:            cfg.MetricsScrubSalt,
			})
		}
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
		_, _ = fmt.Fprintf(w, "awg_peer_persistent_keepalive_seconds{%s} %d\n", labels, peer.PersistentKeepalive)
		// With server-side persistent keepalive disabled, an idle AWG peer's
		// handshake age is not a server-side liveness signal; external alerts
		// must not treat this metric as proof that the peer is offline.
		_, _ = fmt.Fprintf(w, "awg_peer_last_handshake_time_seconds{%s} %d\n", labels, peer.LastHandshakeSec)
	}
}

func scrubbedPeerLabel(salt, peerHex string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(salt) + "\x00" + strings.TrimSpace(peerHex)))
	return "peer_" + hex.EncodeToString(sum[:8])
}

func loadMetricsScrubSalt(stateDir, override string) (string, error) {
	if salt := strings.TrimSpace(override); salt != "" {
		return salt, nil
	}
	path := filepath.Join(stateDir, metricsScrubSaltFile)
	if raw, err := os.ReadFile(path); err == nil {
		salt := strings.TrimSpace(string(raw))
		if salt != "" {
			_ = os.Chmod(path, 0o600)
			return salt, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	salt := hex.EncodeToString(raw)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(salt+"\n"), 0o600); err != nil {
		return "", err
	}
	return salt, nil
}
