package main

import (
	"testing"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/serverpeer"
)

func TestBuildRealityUsageReportsMapsPerUserStats(t *testing.T) {
	raw := []byte(`{
  "stat": [
    {"name":"user>>>device-a>>>traffic>>>uplink","value":"60"},
    {"name":"user>>>device-a>>>traffic>>>downlink","value":40},
    {"name":"user>>>p0-smoke>>>traffic>>>uplink","value":"999"}
  ]
}`)
	reports, err := buildRealityUsageReports([]approvedDevice{{
		DeviceID:    "device-a",
		RealityUUID: "uuid-a",
		Status:      "approved",
	}, {
		DeviceID:    "device-b",
		RealityUUID: "uuid-b",
		Status:      "approved",
	}}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 {
		t.Fatalf("reports=%d want 2: %+v", len(reports), reports)
	}
	if reports[0].DeviceID != "device-a" || reports[0].Source != realityUsageSource || reports[0].RxBytes != 60 || reports[0].TxBytes != 40 {
		t.Fatalf("bad device-a report: %+v", reports[0])
	}
	if reports[1].DeviceID != "device-b" || reports[1].RxBytes != 0 || reports[1].TxBytes != 0 {
		t.Fatalf("zero baseline missing for device-b: %+v", reports[1])
	}
}

func TestAccumulateRealityUsageSurvivesCounterResets(t *testing.T) {
	state := usageState{}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	accumulateRealityUsage([]orchUsageReport{{DeviceID: "a", Source: realityUsageSource, RxBytes: 100, TxBytes: 10}}, state, now)
	reports := accumulateRealityUsage([]orchUsageReport{{DeviceID: "a", Source: realityUsageSource, RxBytes: 5, TxBytes: 1}}, state, now.Add(time.Minute))
	if len(reports) != 1 || reports[0].RxBytes != 105 || reports[0].TxBytes != 11 {
		t.Fatalf("totals must keep growing across reset queries: %+v", reports)
	}
	state["reality:stale"] = usageSnapshot{RxBytes: 1, UpdatedAt: now.Add(-usageStateRetention - time.Hour)}
	accumulateRealityUsage(nil, state, now.Add(2*time.Minute))
	if _, ok := state["reality:stale"]; ok {
		t.Fatal("stale usage entry was not pruned")
	}
	if _, ok := state["reality:a"]; !ok {
		t.Fatal("fresh usage entry was pruned")
	}
}

func TestCollectWorkerUsageReportsKeepsAWGWhenXrayStatsUnavailable(t *testing.T) {
	pub := keyB64(9)
	pubHex, err := serverpeer.KeyB64ToHex(pub)
	if err != nil {
		t.Fatal(err)
	}
	socketPath, _ := startFakeUAPIServer(t, []string{
		"public_key=" + pubHex,
		"rx_bytes=10",
		"tx_bytes=20",
		"errno=0",
		"",
		"",
	})
	cfg := envConfig{
		StateDir:      t.TempDir(),
		AWGUAPISocket: socketPath,
	}
	reports := collectWorkerUsageReports(cfg, desiredState{realityEnabled: true, awgEnabled: true, devices: []approvedDevice{{
		DeviceID:     "device-a",
		RealityUUID:  "uuid-a",
		AWGPublicKey: pub,
		Status:       "approved",
	}}})
	if len(reports) != 1 || reports[0].AWGPublicKey != pub || reports[0].RxBytes != 10 || reports[0].TxBytes != 20 {
		t.Fatalf("AWG usage lost when Xray stats unavailable: %+v", reports)
	}
}

func TestQueryXrayStatsResetsCounters(t *testing.T) {
	fx := &fakeXrayAPI{}
	installFakeXrayAPI(t, fx)
	raw, err := queryXrayStats(envConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"stat":[]}` {
		t.Fatalf("stats output=%q", raw)
	}
	if len(fx.calls) != 1 || fx.calls[0][0] != "statsquery" || !containsString(fx.calls[0], "-reset=true") {
		t.Fatalf("unexpected xray api call: %v", fx.calls)
	}
}
