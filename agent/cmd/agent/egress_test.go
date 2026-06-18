package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReconcileBootstrapEgressOverridesPersistedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	st := stateFile{EgressIP: "172.18.0.2"}

	updated, err := reconcileBootstrapEgress(path, envConfig{EgressIP: "203.0.113.7"}, st)
	if err != nil {
		t.Fatal(err)
	}
	if updated.EgressIP != "203.0.113.7" {
		t.Fatalf("egress override not applied: %q", updated.EgressIP)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved stateFile
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.EgressIP != "203.0.113.7" {
		t.Fatalf("egress override not persisted: %q", saved.EgressIP)
	}
}

func TestIsPublicIPRejectsDockerInternal(t *testing.T) {
	if isPublicIP("172.18.0.2") {
		t.Fatal("docker-private address treated as public")
	}
	if !isPublicIP("203.0.113.7") {
		t.Fatal("global unicast address rejected")
	}
}
