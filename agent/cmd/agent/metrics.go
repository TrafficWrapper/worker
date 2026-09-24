package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"
const metricsScrubSaltFile = "metrics_salt"

var (
	quotaBlocksTotal        atomic.Uint64
	awgPeerPolicyDriftTotal atomic.Uint64
	uapiErrorsTotal         atomic.Uint64
	dockerExecErrorsTotal   atomic.Uint64

	orchAppliedSeqGauge     atomic.Int64
	orchDesiredSeqGauge     atomic.Int64
	orchLastSuccessUnix     atomic.Int64
	approvedDevicesGauge    atomic.Int64
	applyDurationMillis     atomic.Int64
	awgReconcileMillisTotal atomic.Int64

	orchRequestsTotal = newCounterVec()
	xrayApplyTotal    = newCounterVec()
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// counterVec is a minimal labelled counter keyed by a rendered label set.
type counterVec struct {
	mu     sync.Mutex
	values map[string]uint64
}

func newCounterVec() *counterVec {
	return &counterVec{values: map[string]uint64{}}
}

func (c *counterVec) inc(labels string) {
	c.mu.Lock()
	c.values[labels]++
	c.mu.Unlock()
}

func (c *counterVec) get(labels string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.values[labels]
}

func (c *counterVec) snapshot() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]uint64, len(c.values))
	for k, v := range c.values {
		out[k] = v
	}
	return out
}

func orchRequestLabels(op, result string) string {
	return fmt.Sprintf("{op=%q,result=%q}", op, result)
}

func recordOrchRequest(op string, err error) {
	result := "ok"
	if err != nil {
		result = "error"
	} else {
		orchLastSuccessUnix.Store(time.Now().Unix())
	}
	orchRequestsTotal.inc(orchRequestLabels(op, result))
}

func recordXrayApply(mode string) {
	xrayApplyTotal.inc(fmt.Sprintf("{mode=%q}", mode))
}

// metricsWriter groups samples by family so every family is emitted once with
// its HELP and TYPE lines, as the Prometheus text format expects.
type metricsWriter struct {
	order    []string
	families map[string]*metricFamily
}

type metricFamily struct {
	help    string
	typ     string
	samples []string
}

func newMetricsWriter() *metricsWriter {
	return &metricsWriter{families: map[string]*metricFamily{}}
}

func (m *metricsWriter) add(name, typ, help, labels string, value any) {
	family, ok := m.families[name]
	if !ok {
		family = &metricFamily{help: help, typ: typ}
		m.families[name] = family
		m.order = append(m.order, name)
	}
	family.samples = append(family.samples, fmt.Sprintf("%s%s %v", name, labels, value))
}

func (m *metricsWriter) writeTo(w io.Writer) {
	for _, name := range m.order {
		family := m.families[name]
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, family.help, name, family.typ)
		for _, sample := range family.samples {
			_, _ = fmt.Fprintln(w, sample)
		}
	}
}

func metricsHandler(cfg envConfig, startedAt time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", metricsContentType)
		m := newMetricsWriter()
		writeAgentMetrics(m, cfg)
		opts := metricsOptions{ScrubPeerLabels: cfg.MetricsScrubPeerLabels, Salt: cfg.MetricsScrubSalt}
		for _, snapshot := range collectAWGProfilePeerSnapshots(cfg) {
			if snapshot.Error != "" {
				m.add("tw_worker_awg_interface_up", "gauge", "AWG interface answers UAPI.", fmt.Sprintf("{interface=%q}", snapshot.Interface), 0)
				m.add("tw_worker_awg_scrape_error", "gauge", "AWG UAPI scrape failed.", fmt.Sprintf("{interface=%q,error=%q}", snapshot.Interface, snapshot.Error), 1)
				continue
			}
			addAWGMetrics(m, snapshot.Interface, startedAt, snapshot.Peers, opts)
		}
		m.writeTo(w)
	}
}

func writeAgentMetrics(m *metricsWriter, cfg envConfig) {
	m.add("tw_worker_build_info", "gauge", "Worker agent build information.", fmt.Sprintf("{version=%q}", version), 1)
	m.add("awg_peer_policy_drift_total", "counter", "AWG peer policy drifts repaired by reconcile.", "", awgPeerPolicyDriftTotal.Load())
	m.add("tw_worker_uapi_errors_total", "counter", "Failed AWG UAPI operations.", "", uapiErrorsTotal.Load())
	m.add("tw_worker_docker_exec_errors_total", "counter", "Failed docker exec calls into the Xray container.", "", dockerExecErrorsTotal.Load())
	m.add("tw_worker_orch_applied_seq", "gauge", "Worker config sequence applied by this worker.", "", orchAppliedSeqGauge.Load())
	m.add("tw_worker_orch_desired_seq", "gauge", "Latest worker config sequence announced by the orchestrator.", "", orchDesiredSeqGauge.Load())
	m.add("tw_worker_orch_last_success_timestamp_seconds", "gauge", "Unix time of the last successful orchestrator request.", "", orchLastSuccessUnix.Load())
	m.add("tw_worker_approved_devices", "gauge", "Unexpired approved devices in the applied config.", "", approvedDevicesGauge.Load())
	m.add("tw_worker_apply_duration_seconds", "gauge", "Duration of the last worker config apply.", "", float64(applyDurationMillis.Load())/1000)
	m.add("tw_worker_awg_reconcile_seconds_total", "counter", "Total time spent in periodic AWG reconcile.", "", float64(awgReconcileMillisTotal.Load())/1000)
	for _, labels := range sortedKeys(orchRequestsTotal.snapshot()) {
		m.add("tw_worker_orch_requests_total", "counter", "Orchestrator requests by operation and result.", labels, orchRequestsTotal.get(labels))
	}
	for _, labels := range sortedKeys(xrayApplyTotal.snapshot()) {
		m.add("tw_worker_xray_apply_total", "counter", "Xray config applies by mode (live, restart, failed).", labels, xrayApplyTotal.get(labels))
	}
	if expiry, ok := distributorCertExpiry(cfg); ok {
		m.add("tw_worker_distributor_cert_expiry_seconds", "gauge", "Seconds until the distributor certificate expires.", "", int64(time.Until(expiry).Seconds()))
	}
	m.add("tw_worker_quota_blocks_total", "counter", "Quota blocks reported by the orchestrator.", "", quotaBlocksTotal.Load())
	health := healthSnapshot()
	for _, probe := range []struct {
		name   string
		report *probeReport
	}{{"camouflage", health.Camouflage}, {"reality", health.Reality}} {
		name, report := probe.name, probe.report
		if report == nil {
			continue
		}
		ok := 0
		if report.OK {
			ok = 1
		}
		m.add("tw_worker_probe_ok", "gauge", "Result of the last camouflage/REALITY probe (1 = healthy).", fmt.Sprintf("{probe=%q}", name), ok)
	}
}

func sortedKeys(values map[string]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func distributorCertExpiry(cfg envConfig) (time.Time, bool) {
	if cfg.StateDir == "" {
		return time.Time{}, false
	}
	raw, err := os.ReadFile(filepath.Join(cfg.StateDir, "distributor", "certs", "tls.crt"))
	if err != nil {
		return time.Time{}, false
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return time.Time{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, false
	}
	return cert.NotAfter, true
}

type metricsOptions struct {
	ScrubPeerLabels bool
	Salt            string
}

func writeAWGMetricsWithOptions(w io.Writer, iface string, startedAt time.Time, peers []awgPeerConfig, opts metricsOptions) {
	m := newMetricsWriter()
	addAWGMetrics(m, iface, startedAt, peers, opts)
	m.writeTo(w)
}

func addAWGMetrics(m *metricsWriter, iface string, startedAt time.Time, peers []awgPeerConfig, opts metricsOptions) {
	ifaceLabel := fmt.Sprintf("{interface=%q}", iface)
	m.add("tw_worker_awg_interface_up", "gauge", "AWG interface answers UAPI.", ifaceLabel, 1)
	m.add("tw_worker_awg_peer_count", "gauge", "Configured AWG peers.", ifaceLabel, len(peers))
	m.add("tw_worker_awg_metrics_uptime_seconds", "gauge", "Seconds since the agent started.", ifaceLabel, fmt.Sprintf("%.0f", time.Since(startedAt).Seconds()))
	// Kept per interface for existing dashboards; the unlabelled series is the
	// canonical one.
	m.add("tw_worker_quota_blocks_total", "counter", "Quota blocks reported by the orchestrator.", ifaceLabel, quotaBlocksTotal.Load())
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
		labels = "{" + labels + "}"
		m.add("awg_peer_rx_bytes", "counter", "Bytes received from the AWG peer.", labels, peer.RxBytes)
		m.add("awg_peer_tx_bytes", "counter", "Bytes sent to the AWG peer.", labels, peer.TxBytes)
		m.add("awg_peer_persistent_keepalive_seconds", "gauge", "Server-side persistent keepalive of the AWG peer.", labels, peer.PersistentKeepalive)
		// With server-side persistent keepalive disabled, an idle AWG peer's
		// handshake age is not a server-side liveness signal; external alerts
		// must not treat this metric as proof that the peer is offline.
		m.add("awg_peer_last_handshake_time_seconds", "gauge", "Unix time of the last AWG handshake with the peer.", labels, peer.LastHandshakeSec)
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
