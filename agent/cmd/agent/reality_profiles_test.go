package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRealityProfilesValidates(t *testing.T) {
	profiles, err := parseRealityProfiles(`[{"name":"XH","network":"xhttp","listen_port":8444,"public_port":2083,"xhttp_path":"/x"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Name != "xh" || profiles[0].tag() != "reality-xh" || profiles[0].PublicPort != 2083 {
		t.Fatalf("profiles=%+v", profiles)
	}
	for _, bad := range []string{
		`[{"name":"reality","listen_port":8444}]`,
		`[{"name":"a","listen_port":8443}]`,
		`[{"name":"a","listen_port":10085}]`,
		`[{"name":"a","network":"grpc","listen_port":8444}]`,
		`[{"name":"a","network":"xhttp","listen_port":8444}]`,
		`[{"name":"a","listen_port":8444},{"name":"b","listen_port":8444}]`,
		`[{"name":"in","listen_port":8444}]`,
	} {
		if _, err := parseRealityProfiles(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestRealityFlowIsPerDeviceAndTCPOnly(t *testing.T) {
	profiles, _ := parseRealityProfiles(`[{"name":"xh","network":"xhttp","listen_port":8444,"xhttp_path":"/x"}]`)
	cfg := envConfig{RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net", RealityProfiles: profiles, DisableSmokePeers: true}
	vision := realityDevice("v", "4fad2182-6de3-4407-bf8f-d8c688160ce6")
	vision.RealityFlow = flowVision
	plain := realityDevice("p", "4fad2182-6de3-4407-bf8f-d8c688160ce7")
	doc := xrayConfigDocument(cfg, hardeningTestState(), []approvedDevice{vision, plain})
	inbounds := doc["inbounds"].([]any)
	flows := func(i int) []any {
		var out []any
		for _, c := range inbounds[i].(map[string]any)["settings"].(map[string]any)["clients"].([]any) {
			out = append(out, c.(map[string]any)["flow"])
		}
		return out
	}
	if got := flows(0); got[0] != flowVision || got[1] != nil {
		t.Fatalf("tcp flows=%v", got)
	}
	if got := flows(1); got[0] != nil || got[1] != nil {
		t.Fatalf("xhttp must not carry vision: %v", got)
	}
	if _, err := normalizeApprovedDevice(approvedDevice{RealityUUID: "4fad2182-6de3-4407-bf8f-d8c688160ce6", RealityFlow: "xtls-rprx-direct", AWGPublicKey: keyB64(1), PSK2: keyB64(2), InternalIP: "10.13.13.5"}); err == nil {
		t.Fatal("unsupported flow accepted")
	}
}

func TestRealityCohortsAndRevocation(t *testing.T) {
	st := stateFile{Reality: realityState{ShortID: "abcd"}}
	if !ensureRealityCohorts(&st) || len(st.Reality.CohortShortIDs) != realityCohortCount || ensureRealityCohorts(&st) {
		t.Fatalf("cohort backfill wrong: %v", st.Reality.CohortShortIDs)
	}
	revoked := st.Reality.CohortShortIDs[3]
	stateDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, "orch"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := `{"desired_state":{"approved_devices":[],"revoked_short_ids":["` + strings.ToUpper(revoked) + `"]}}`
	if err := os.WriteFile(filepath.Join(stateDir, "orch", "worker-config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	ids := realityShortIDs(st, revokedShortIDs(stateDir))
	if len(ids) != realityCohortCount || ids[0] != "abcd" || containsString(ids, revoked) {
		t.Fatalf("short ids=%v", ids)
	}
	published := publishedCohortShortIDs(st)
	if len(published) != realityCohortCount || published[3] != revoked || containsString(published, "abcd") {
		t.Fatalf("published cohorts must keep every slot in generation order: %v", published)
	}
	for i, id := range st.Reality.CohortShortIDs {
		if published[i] != id {
			t.Fatalf("slot %d moved: %v", i, published)
		}
	}
}

func TestDiffXrayUsersCoversEveryRealityInbound(t *testing.T) {
	profiles, _ := parseRealityProfiles(`[{"name":"xh","network":"xhttp","listen_port":8444,"xhttp_path":"/x"}]`)
	cfg := envConfig{RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net", RealityProfiles: profiles}
	st := hardeningTestState()
	oldRaw, _ := xrayConfigBytes(cfg, st, nil)
	newRaw, _ := xrayConfigBytes(cfg, st, []approvedDevice{realityDevice("a", "4fad2182-6de3-4407-bf8f-d8c688160ce6")})
	diffs, err := diffXrayUsers(oldRaw, newRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(diffs) != 2 || diffs[0].Tag != "reality-in" || diffs[1].Tag != "reality-xh" || len(diffs[1].Add) != 1 {
		t.Fatalf("diffs=%+v", diffs)
	}
}

func TestAWGProfileOwnDialectIsGeneratedOnceAndAdvertised(t *testing.T) {
	cfg := envConfig{AWGProfiles: []awgInboundProfile{
		{Name: "awg", Interface: "awg1", ListenPort: 51821, Subnet: "10.13.13.0/24"},
		{Name: "next", Interface: "awg2", ListenPort: 51822, Subnet: "10.44.0.0/24", OwnDialect: true},
	}}
	base, err := generateDialect()
	if err != nil {
		t.Fatal(err)
	}
	st := stateFile{Dialect: base}
	changed, err := ensureProfileDialects(cfg, &st)
	if err != nil || !changed {
		t.Fatalf("changed=%t err=%v", changed, err)
	}
	next := st.ProfileDialects["next"]
	if next == base || profileDialect(st, cfg.AWGProfiles[1]) != next || profileDialect(st, cfg.AWGProfiles[0]) != base {
		t.Fatal("profile dialect not isolated from the worker dialect")
	}
	if changed, _ := ensureProfileDialects(cfg, &st); changed {
		t.Fatal("existing profile dialect regenerated")
	}
	if profileDialectID(st, cfg.AWGProfiles[1]) == profileDialectID(st, cfg.AWGProfiles[0]) {
		t.Fatal("profile dialect id not distinct")
	}
}

func TestBaseShortIDCannotBeRevoked(t *testing.T) {
	st := stateFile{Reality: realityState{ShortID: "abcd"}}
	ensureRealityCohorts(&st)
	ids := realityShortIDs(st, []string{"ABCD", st.Reality.CohortShortIDs[0]})
	if len(ids) == 0 || ids[0] != "abcd" || containsString(ids, st.Reality.CohortShortIDs[0]) {
		t.Fatalf("short ids=%v", ids)
	}
}

func TestXrayConfigWithoutShortIDsIsNeverWritten(t *testing.T) {
	t.Cleanup(func() { xrayConfigRejected.Store(false) })
	cfg := envConfig{StateDir: t.TempDir(), RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net", DisableSmokePeers: true}
	good := hardeningTestState()
	good.Reality.CohortShortIDs = []string{"c1"}
	if err := renderXray(cfg, good); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(xrayConfigPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	// Every short ID gone: no base and the only cohort revoked.
	broken := good
	broken.Reality.ShortID = ""
	if err := writeFile(filepath.Join(cfg.StateDir, "orch", "worker-config.json"), []byte(`{"desired_state":{"approved_devices":[],"revoked_short_ids":["c1"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := xrayConfigBytes(cfg, broken, nil); !errors.Is(err, errNoShortIDs) {
		t.Fatalf("empty shortIds rendered: %v", err)
	}
	if err := renderXray(cfg, broken); err != nil {
		t.Fatalf("startup render must keep going: %v", err)
	}
	if err := applyDesiredState(cfg, broken, desiredState{realityEnabled: true, awgEnabled: true}); err == nil {
		t.Fatal("apply with empty shortIds reported success")
	}
	now, _ := os.ReadFile(xrayConfigPath(cfg))
	if string(now) != string(valid) {
		t.Fatal("last valid xray config replaced")
	}
	if !strings.Contains(selfCheckStatus(), "xray_config") {
		t.Fatalf("self_check %q does not report the refused config", selfCheckStatus())
	}
}
