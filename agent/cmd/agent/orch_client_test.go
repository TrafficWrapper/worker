package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"aead.dev/minisign"
)

func TestVerifyOrchBundleRejectsUnsignedAndRollback(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubText := mustMarshalText(t, pub)
	config := `{"ns":"worker-config-v1","seq":1}`
	sig := string(minisign.Sign(priv, []byte(config)))
	if _, err := verifyOrchBundle(orchSignedConfig{ConfigJSON: config, PublicKey: pubText}, pubText, 0, "worker-config-v1"); err == nil {
		t.Fatal("unsigned bundle accepted")
	}
	if _, err := verifyOrchBundle(orchSignedConfig{ConfigJSON: config, Minisig: sig, PublicKey: pubText}, pubText, 1, "worker-config-v1"); err == nil {
		t.Fatal("rollback bundle accepted")
	}
	if seq, err := verifyOrchBundle(orchSignedConfig{ConfigJSON: config, Minisig: sig, PublicKey: pubText}, pubText, 0, "worker-config-v1"); err != nil || seq != 1 {
		t.Fatalf("signed bundle rejected: seq=%d err=%v", seq, err)
	}
}

func TestApplyOrchBundlesAllowsEqualClientSeqAndSkipsStrictRollback(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubText := mustMarshalText(t, pub)
	cfg := envConfig{StateDir: t.TempDir()}
	var st stateFile
	xrayRaw, err := xrayConfigBytes(cfg, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(xrayConfigPath(cfg), xrayRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	state := orchState{SignerPublicKey: pubText, AppliedSeq: 9, ClientAppliedSeq: 5}
	workerBundle := signedBundleForTest(t, priv, pubText, "worker-config-v1", 10, `,"desired_state":{"approved_devices":[]}`)
	equalClient := signedBundleForTest(t, priv, pubText, "client-config-v1", 5, "")
	seq, clientSeq, err := applyOrchBundles(cfg, st, state, workerBundle, equalClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 10 || clientSeq != 5 {
		t.Fatalf("equal client seq apply=(%d,%d), want (10,5)", seq, clientSeq)
	}

	state.AppliedSeq = 10
	state.ClientAppliedSeq = 5
	nextWorker := signedBundleForTest(t, priv, pubText, "worker-config-v1", 11, `,"desired_state":{"approved_devices":[]}`)
	rollbackClient := signedBundleForTest(t, priv, pubText, "client-config-v1", 4, "")
	seq, clientSeq, err = applyOrchBundles(cfg, st, state, nextWorker, rollbackClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 11 || clientSeq != 5 {
		t.Fatalf("rollback client seq apply=(%d,%d), want worker applied and client unchanged (11,5)", seq, clientSeq)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.StateDir, "orch", "worker-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"seq":11`) {
		t.Fatalf("worker bundle was not written after client rollback:\n%s", raw)
	}
}

func signedBundleForTest(t *testing.T, priv minisign.PrivateKey, pubText, ns string, seq int64, extra string) orchSignedConfig {
	t.Helper()
	config := `{"ns":"` + ns + `","seq":` + strconv.FormatInt(seq, 10) + extra + `}`
	return orchSignedConfig{
		ConfigJSON: config,
		Minisig:    string(minisign.Sign(priv, []byte(config))),
		PublicKey:  pubText,
	}
}

func mustMarshalText(t *testing.T, v interface{ MarshalText() ([]byte, error) }) string {
	t.Helper()
	raw, err := v.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
