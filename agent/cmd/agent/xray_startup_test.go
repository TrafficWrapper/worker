package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderXrayAppliesSettingChangesWithoutDevices(t *testing.T) {
	cfg := envConfig{StateDir: t.TempDir(), RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net", DisableSmokePeers: true}
	st := hardeningTestState()
	if err := renderXray(cfg, st); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.StateDir, "xray", "restart-request")); err != nil {
		t.Fatal(err)
	}
	// The operator changes the camouflage target; there are still no devices.
	cfg.RealityDest = "www.example.org:443"
	cfg.CamouflageDomain = "www.example.org"
	if err := renderXray(cfg, st); err != nil {
		t.Fatal(err)
	}
	if !restartRequested(cfg) {
		t.Fatal("changed settings written but Xray not restarted")
	}
}

func TestRenderXrayAntiWipeKeepsUsers(t *testing.T) {
	cfg := envConfig{StateDir: t.TempDir(), RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net", DisableSmokePeers: true}
	st := hardeningTestState()
	withUser, _ := xrayConfigBytes(cfg, st, []approvedDevice{realityDevice("device-a", "4fad2182-6de3-4407-bf8f-d8c688160ce6")})
	if err := writeXrayConfigBytes(cfg, withUser); err != nil {
		t.Fatal(err)
	}
	if err := saveOrchState(cfg.StateDir, orchState{WorkerID: "w", AppliedSeq: 5}); err != nil {
		t.Fatal(err)
	}
	for name, cache := range map[string]*string{
		"missing cache":       nil,
		"unsigned empty list": ptr(`{"desired_state":{"approved_devices":[]}}`),
	} {
		cachePath := filepath.Join(cfg.StateDir, "orch", "worker-config.json")
		_ = os.Remove(cachePath)
		if cache != nil {
			if err := writeFile(cachePath, []byte(*cache), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := renderXray(cfg, st); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(xrayConfigPath(cfg))
		if !strings.Contains(string(raw), "device-a") || restartRequested(cfg) {
			t.Fatalf("%s: startup render wiped REALITY users", name)
		}
	}
}

func ptr(s string) *string { return &s }

func TestApplyXrayConfigRestartsWhenFileWasNeverApplied(t *testing.T) {
	fx := &fakeXrayAPI{}
	installFakeXrayAPI(t, fx)
	cfg := envConfig{StateDir: t.TempDir(), RealityDest: "www.example.net:443", CamouflageDomain: "www.example.net"}
	st := hardeningTestState()
	a := realityDevice("device-a", "4fad2182-6de3-4407-bf8f-d8c688160ce6")
	b := realityDevice("device-b", "4fad2182-6de3-4407-bf8f-d8c688160ce7")
	applied, _ := xrayConfigBytes(cfg, st, []approvedDevice{a})
	recordXrayAppliedHash(cfg, applied)
	// The file on disk differs from what Xray was last given.
	other := cfg
	other.RealityDest = "www.example.org:443"
	stale, _ := xrayConfigBytes(other, st, []approvedDevice{a})
	if err := writeXrayConfigBytes(cfg, stale); err != nil {
		t.Fatal(err)
	}
	next, _ := xrayConfigBytes(other, st, []approvedDevice{a, b})
	if err := applyXrayConfig(cfg, next, 2); err != nil {
		t.Fatal(err)
	}
	if !restartRequested(cfg) || len(fx.calls) != 0 {
		t.Fatalf("live diff against a file Xray never loaded (calls %v)", fx.calls)
	}
	if got, _ := xrayAppliedHash(cfg); got != sha256HexBytes(next) {
		t.Fatal("applied hash not updated")
	}
}
