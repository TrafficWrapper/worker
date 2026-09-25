package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/serverpeer"
)

func TestRealityUsageTotalsFromAbsoluteCounters(t *testing.T) {
	state := usageState{}
	now := time.Now().UTC()
	var total uint64
	for _, counter := range []uint64{100, 150, 20} { // 20: Xray restarted
		reports := accumulateRealityUsage([]orchUsageReport{{DeviceID: "a", Source: realityUsageSource, RxBytes: counter}}, state, now)
		total = reports[0].RxBytes
	}
	if total != 170 {
		t.Fatalf("total %d, want 170", total)
	}
}

// statsFor returns a fake statsquery answer for device-a.
func installStatsAPI(t *testing.T, rx string) *fakeXrayAPI {
	t.Helper()
	fx := &fakeXrayAPI{}
	old := runXrayAPI
	runXrayAPI = func(_ envConfig, _ time.Duration, subcommand string, args ...string) ([]byte, error) {
		fx.mu.Lock()
		defer fx.mu.Unlock()
		fx.calls = append(fx.calls, append([]string{subcommand}, args...))
		return []byte(`{"stat":[{"name":"user>>>device-a>>>traffic>>>uplink","value":"` + rx + `"}]}`), nil
	}
	t.Cleanup(func() { runXrayAPI = old })
	return fx
}

func TestRealityUsageNotReportedWhenStateCannotBeSaved(t *testing.T) {
	installStatsAPI(t, "500")
	stateDir := t.TempDir()
	// A file where the xray directory should be makes every save fail.
	if err := os.WriteFile(filepath.Join(stateDir, "xray"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	devices := []approvedDevice{{DeviceID: "device-a", RealityUUID: "4fad2182-6de3-4407-bf8f-d8c688160ce6", Status: "approved"}}
	reports, err := collectRealityUsageReports(envConfig{StateDir: stateDir}, devices)
	if err == nil || reports != nil {
		t.Fatalf("usage reported without saved totals: %+v %v", reports, err)
	}

	// Once saving works again the traffic is still counted: nothing was reset.
	if err := os.Remove(filepath.Join(stateDir, "xray")); err != nil {
		t.Fatal(err)
	}
	reports, err = collectRealityUsageReports(envConfig{StateDir: stateDir}, devices)
	if err != nil || len(reports) != 1 || reports[0].RxBytes != 500 {
		t.Fatalf("reports %+v err %v", reports, err)
	}
}

func TestAWGUsageTotalNeverDecreasesWhenAPeerGoesAway(t *testing.T) {
	pub := keyB64(9)
	pubHex, err := serverpeer.KeyB64ToHex(pub)
	if err != nil {
		t.Fatal(err)
	}
	devices := []approvedDevice{{DeviceID: "device-a", AWGPublicKey: pub}}
	now := time.Now().UTC()
	both := []awgPeerConfig{
		{Profile: "awg", PublicKeyHex: pubHex, RxBytes: 100, TxBytes: 10},
		{Profile: "awg2", PublicKeyHex: pubHex, RxBytes: 1000, TxBytes: 100},
	}
	reports, state := buildAWGUsageReports(devices, both, nil, now)
	if reports[0].RxBytes != 1100 || reports[0].TxBytes != 110 {
		t.Fatalf("first total %+v", reports[0])
	}
	// awg2 is removed (dialect rotation): its traffic stays in the total.
	reports, state = buildAWGUsageReports(devices, []awgPeerConfig{{Profile: "awg", PublicKeyHex: pubHex, RxBytes: 130, TxBytes: 13}}, state, now.Add(time.Minute))
	if reports[0].RxBytes != 1130 || reports[0].TxBytes != 113 {
		t.Fatalf("total after profile removal %+v", reports[0])
	}
	// Profile order changing does not mix up the counters either.
	reports, _ = buildAWGUsageReports(devices, []awgPeerConfig{
		{Profile: "awg3", PublicKeyHex: pubHex, RxBytes: 5},
		{Profile: "awg", PublicKeyHex: pubHex, RxBytes: 140},
	}, state, now.Add(2*time.Minute))
	if reports[0].RxBytes != 1145 {
		t.Fatalf("total after reorder %+v", reports[0])
	}
}

func TestAWGUsageTakesOverLegacyStateEntries(t *testing.T) {
	pub := keyB64(9)
	pubHex, _ := serverpeer.KeyB64ToHex(pub)
	devices := []approvedDevice{{DeviceID: "device-a", AWGPublicKey: pub}}
	legacy := awgUsageState{
		"device-a:" + pub + ":0": {RxBytes: 500, LastRxBytes: 100},
		// A peer that was already gone before the upgrade was not part of
		// the reported total and must not be added to it now.
		"device-a:" + pub + ":1": {RxBytes: 7000, LastRxBytes: 7000, UpdatedAt: time.Now().Add(-time.Hour)},
	}
	reports, next := buildAWGUsageReports(devices, []awgPeerConfig{{Profile: "awg", PublicKeyHex: pubHex, RxBytes: 150}}, legacy, time.Now().UTC())
	if reports[0].RxBytes != 550 {
		t.Fatalf("total %d, want 550", reports[0].RxBytes)
	}
	if _, ok := next["device-a:"+pub+":0"]; ok {
		t.Fatal("legacy entry kept after takeover")
	}
}

func TestAWGUsagePruneKeepsEntriesOfLiveDevices(t *testing.T) {
	now := time.Now().UTC()
	state := usageState{
		"a:k:@old": {Device: "a", RxBytes: 5, UpdatedAt: now.Add(-usageStateRetention - time.Hour)},
		"a:k:@new": {Device: "a", RxBytes: 1, UpdatedAt: now},
		"b:k:@x":   {Device: "b", RxBytes: 1, UpdatedAt: now.Add(-usageStateRetention - time.Hour)},
	}
	state.pruneAWG(now)
	if _, ok := state["a:k:@old"]; !ok {
		t.Fatal("old entry of a live device pruned; its total would drop")
	}
	if _, ok := state["b:k:@x"]; ok {
		t.Fatal("entries of a gone device kept")
	}
}

func TestAWGUsageSourceOnlyWithOrchestratorCapability(t *testing.T) {
	t.Cleanup(func() { recordOrchestratorCapabilities(nil) })
	pub := keyB64(9)
	pubHex, _ := serverpeer.KeyB64ToHex(pub)
	socketPath, _ := startFakeUAPIServer(t, []string{"public_key=" + pubHex, "rx_bytes=10", "tx_bytes=20", "errno=0", "", ""})
	ds := desiredState{awgEnabled: true, devices: []approvedDevice{{DeviceID: "device-a", AWGPublicKey: pub, Status: "approved"}}}
	for _, tc := range []struct {
		caps []string
		want string
	}{
		{nil, ""},
		{[]string{"telemetry_batch_v1"}, ""},
		{[]string{"usage_source_awg_v1"}, "awg"},
	} {
		recordOrchestratorCapabilities(tc.caps)
		reports := collectWorkerUsageReports(envConfig{StateDir: t.TempDir(), AWGUAPISocket: socketPath}, ds)
		if len(reports) != 1 || reports[0].Source != tc.want || reports[0].DeviceID != "device-a" || !strings.HasPrefix(reports[0].AWGPublicKey, pub[:4]) {
			t.Fatalf("caps %v: %+v", tc.caps, reports)
		}
	}
}
