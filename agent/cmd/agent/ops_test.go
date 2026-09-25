package main

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/serverpeer"
)

func TestSyncAWGUAPISendsOnlyTheDifferenceInOneSet(t *testing.T) {
	keep, keepHex := keyB64(21), ""
	add := keyB64(22)
	var err error
	if keepHex, err = serverpeer.KeyB64ToHex(keep); err != nil {
		t.Fatal(err)
	}
	staleHex := strings.Repeat("c", 64)
	fake := startStatefulFakeUAPI(t, []awgPeerConfig{
		{PublicKeyHex: keepHex, AllowedIPs: []string{"10.13.13.10/32"}, PersistentKeepalive: 0},
		{PublicKeyHex: staleHex, AllowedIPs: []string{"10.13.13.99/32"}, PersistentKeepalive: 0},
	})
	desired := []awgDesiredPeer{
		{PublicKey: keep, PSK2: keyB64(1), AllowedIP: "10.13.13.10/32"},
		{PublicKey: add, PSK2: keyB64(1), AllowedIP: "10.13.13.11/32"},
	}
	if err := syncAWGUAPI(fake.socketPath, desired, 0); err != nil {
		t.Fatal(err)
	}
	if _, sets := fake.counts(); sets != 1 {
		t.Fatalf("expected one batched set operation, got %d", sets)
	}
	if _, ok := fake.peer(staleHex); ok {
		t.Fatal("stale peer not removed")
	}
	addHex, _ := serverpeer.KeyB64ToHex(add)
	if _, ok := fake.peer(addHex); !ok {
		t.Fatal("new peer not added")
	}
	fake.mu.Lock()
	last := fake.requests[len(fake.requests)-1]
	fake.mu.Unlock()
	if strings.Contains(last, "public_key="+keepHex) {
		t.Fatalf("unchanged peer was rewritten:\n%s", last)
	}

	if err := syncAWGUAPI(fake.socketPath, desired, 0); err != nil {
		t.Fatal(err)
	}
	if _, sets := fake.counts(); sets != 1 {
		t.Fatalf("converged device must not be written again, sets=%d", sets)
	}
}

func TestAWGPeerMatchesComparesReportedPSK(t *testing.T) {
	pskHex, _ := serverpeer.KeyB64ToHex(keyB64(3))
	live := awgPeerConfig{AllowedIPs: []string{"10.13.13.5/32"}, PresharedKeyHex: pskHex}
	want := awgDesiredPeer{PSK2: keyB64(3), AllowedIP: "10.13.13.5/32"}
	if !awgPeerMatches(live, want, 0) {
		t.Fatal("identical peer reported as different")
	}
	want.PSK2 = keyB64(4)
	if awgPeerMatches(live, want, 0) {
		t.Fatal("rotated PSK not detected")
	}
	live.PresharedKeyHex = ""
	if !awgPeerMatches(live, want, 0) {
		t.Fatal("unknown live PSK must not force a rewrite")
	}
}

func TestBackoffGrowsWithJitterAndResets(t *testing.T) {
	b := newBackoff(time.Second, 8*time.Second)
	var last time.Duration
	for i := 0; i < 10; i++ {
		last = b.next()
		if last < 0 || last > 8*time.Second {
			t.Fatalf("delay out of range: %s", last)
		}
	}
	if b.current != 8*time.Second || last < 4*time.Second {
		t.Fatalf("backoff did not saturate: current=%s last=%s", b.current, last)
	}
	b.reset()
	if d := b.next(); d > time.Second {
		t.Fatalf("reset backoff delay=%s", d)
	}
}

func TestMetricsExposeAgentSeriesWithTypes(t *testing.T) {
	recordOrchRequest("pull", nil)
	recordXrayApply("live")
	orchAppliedSeqGauge.Store(7)
	orchDesiredSeqGauge.Store(9)
	cfg := envConfig{StateDir: t.TempDir(), CamouflageDomain: "www.example.net", AWGProfiles: []awgInboundProfile{{Name: "awg", Interface: "awg1", UAPISocket: "/nonexistent.sock"}}}
	if err := ensureDistributorCert(cfg); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	metricsHandler(cfg, time.Now())(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE tw_worker_orch_requests_total counter",
		`tw_worker_orch_requests_total{op="pull",result="ok"}`,
		`tw_worker_xray_apply_total{mode="live"}`,
		"tw_worker_orch_applied_seq 7",
		"tw_worker_orch_desired_seq 9",
		"tw_worker_orch_last_success_timestamp_seconds ",
		"tw_worker_distributor_cert_expiry_seconds ",
		`tw_worker_build_info{version="dev"} 1`,
		`tw_worker_awg_interface_up{interface="awg1"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Count(body, "# TYPE tw_worker_quota_blocks_total") != 1 {
		t.Fatalf("family emitted more than once:\n%s", body)
	}
}

func TestParseLogLevelAndAckInterval(t *testing.T) {
	if parseLogLevel("DEBUG") != slog.LevelDebug || parseLogLevel("") != slog.LevelInfo || parseLogLevel("warning") != slog.LevelWarn || parseLogLevel("error") != slog.LevelError {
		t.Fatal("log level parsing is wrong")
	}
	t.Setenv("WORKER_STATE_DIR", t.TempDir())
	t.Setenv("EGRESS_IP", "203.0.113.10")
	t.Setenv("CAMOUFLAGE_DOMAIN", "www.example.net")
	t.Setenv("ORCH_ACK_INTERVAL", "2m")
	cfg, err := readEnv()
	if err != nil || cfg.OrchAckInterval != 2*time.Minute {
		t.Fatalf("ack interval=%s err=%v", cfg.OrchAckInterval, err)
	}
	t.Setenv("ORCH_ACK_INTERVAL", "1s")
	if _, err := readEnv(); err == nil {
		t.Fatal("too short ack interval accepted")
	}
}

func TestCreateFileExclusiveWithoutHardLinks(t *testing.T) {
	old := linkFile
	linkFile = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} }
	t.Cleanup(func() { linkFile = old })
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := createFileExclusive(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != `{"a":1}` {
		t.Fatalf("content %q", raw)
	}
	if err := createFileExclusive(path, []byte(`{"b":2}`), 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second writer not refused: %v", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != `{"a":1}` {
		t.Fatal("first writer's file replaced")
	}
	// A lock left by a crashed writer is broken once it is stale.
	other := filepath.Join(filepath.Dir(path), "other.json")
	if err := os.WriteFile(other+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old2 := time.Now().Add(-time.Hour)
	if err := os.Chtimes(other+".lock", old2, old2); err != nil {
		t.Fatal(err)
	}
	if err := createFileExclusive(other, []byte("x"), 0o600); err != nil {
		t.Fatalf("stale lock not broken: %v", err)
	}
	if fileExists(other + ".lock") {
		t.Fatal("lock left behind")
	}
}

func TestBootstrapRecoversFromEmptyState(t *testing.T) {
	cfg := envConfig{
		StateDir:         t.TempDir(),
		AWGSubnet:        "10.13.13.0/24",
		AWGGateway:       "10.13.13.1",
		CamouflageDomain: "www.example.net",
		RealityDest:      "www.example.net:443",
		EgressIP:         "203.0.113.10",
		PublicAddress:    "203.0.113.10",
	}
	if err := os.WriteFile(filepath.Join(cfg.StateDir, "bootstrap.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := bootstrap(cfg)
	if err != nil {
		t.Fatalf("empty bootstrap state not recovered: %v", err)
	}
	if st.Reality.PrivateKey == "" {
		t.Fatal("no state generated")
	}
}
