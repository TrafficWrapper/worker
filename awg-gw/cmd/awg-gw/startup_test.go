package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
