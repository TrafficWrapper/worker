package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// fakeCommands replaces runCommand for the test and records every command.
// fail decides which commands fail; nil means none do.
func fakeCommands(t *testing.T, fail func(cmd string) bool) *[]string {
	t.Helper()
	var ran []string
	orig := runCommand
	runCommand = func(name string, args ...string) ([]byte, error) {
		cmd := strings.Join(append([]string{name}, args...), " ")
		ran = append(ran, cmd)
		if fail != nil && fail(cmd) {
			return []byte("fake failure"), errors.New("exit status 1")
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommand = orig })
	return &ran
}

func writeTestConfig(t *testing.T, cfg Config) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "awg-gw.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHealthcheckChecksInterfaceOfGivenConfig(t *testing.T) {
	cfg := validTestConfig()
	cfg.Interface = "awg2"
	path := writeTestConfig(t, cfg)

	ran := fakeCommands(t, nil)
	if err := runHealthcheck([]string{"--config", path}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*ran, "\n"); got != "ip link show dev awg2" {
		t.Fatalf("healthcheck ran %q, want the profile interface awg2", got)
	}

	fakeCommands(t, func(string) bool { return true })
	if err := runHealthcheck([]string{"--config", path}); err == nil {
		t.Fatal("missing interface reported healthy")
	}
}

// fakeTUN replaces createTUN and records the commands already run when the
// TUN would be created. It fails, so runGateway stops right after.
func fakeTUN(t *testing.T, ran *[]string) *[]string {
	t.Helper()
	var before []string
	orig := createTUN
	createTUN = func(string, int) (tun.Device, error) {
		before = append([]string(nil), *ran...)
		return nil, errors.New("fake TUN stop")
	}
	t.Cleanup(func() { createTUN = orig })
	return &before
}

func TestGatewayInstallsIsolationBeforeCreatingTUN(t *testing.T) {
	t.Setenv("WORKER_ALLOW_PRIVATE_EGRESS", "")
	t.Setenv("WORKER_BLOCK_SMTP", "")
	t.Setenv("AWG_LOG_LEVEL", "silent")
	path := writeTestConfig(t, validTestConfig())

	ran := fakeCommands(t, nil)
	before := fakeTUN(t, ran)
	err := runGateway(path)
	if err == nil || !strings.Contains(err.Error(), "fake TUN stop") {
		t.Fatalf("runGateway error=%v, want the fake TUN failure", err)
	}
	isolation := strings.Join(*before, "\n")
	for _, want := range []string{"trafficwrapper_awg_isolation forward iifname awg1 ip daddr", "tcp dport { 25, 465, 587 } drop"} {
		if !strings.Contains(isolation, want) {
			t.Fatalf("isolation rule %q not installed before the TUN:\n%s", want, isolation)
		}
	}
}

func TestGatewayDoesNotStartWithoutIsolation(t *testing.T) {
	t.Setenv("WORKER_ALLOW_PRIVATE_EGRESS", "")
	t.Setenv("WORKER_BLOCK_SMTP", "")
	t.Setenv("AWG_LOG_LEVEL", "silent")
	path := writeTestConfig(t, validTestConfig())

	ran := fakeCommands(t, func(cmd string) bool { return strings.Contains(cmd, "_isolation") })
	tunCalled := false
	orig := createTUN
	createTUN = func(string, int) (tun.Device, error) {
		tunCalled = true
		return nil, errors.New("fake TUN stop")
	}
	t.Cleanup(func() { createTUN = orig })

	err := runGateway(path)
	if err == nil || strings.Contains(err.Error(), "fake TUN stop") {
		t.Fatalf("runGateway error=%v, want the isolation failure", err)
	}
	if tunCalled {
		t.Fatalf("TUN created although isolation failed; commands: %v", *ran)
	}
}

func TestHealthcheckRequiresExplicitConfig(t *testing.T) {
	ran := fakeCommands(t, nil)
	missing := filepath.Join(t.TempDir(), "missing.json")
	if err := runHealthcheck([]string{"--config", missing}); err == nil {
		t.Fatal("missing explicit config reported healthy")
	}
	if len(*ran) != 0 {
		t.Fatalf("commands ran without a config: %v", *ran)
	}
}
