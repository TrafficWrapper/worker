package main

import (
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
	if containsString(activeCohortShortIDs(st, revokedShortIDs(stateDir)), "abcd") {
		t.Fatal("base short id listed as a cohort")
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
