package main

import (
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

func TestApplyOrchBundlesRejectsClientBundleRollback(t *testing.T) {
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
	rollbackClient := signedBundleForTest(t, priv, pubText, "client-config-v1", 5, "")
	if _, _, err := applyOrchBundles(cfg, st, state, workerBundle, rollbackClient, nil); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("client rollback accepted or wrong error: %v", err)
	}
	nextClient := signedBundleForTest(t, priv, pubText, "client-config-v1", 6, "")
	seq, clientSeq, err := applyOrchBundles(cfg, st, state, workerBundle, nextClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 10 || clientSeq != 6 {
		t.Fatalf("seq=(%d,%d), want (10,6)", seq, clientSeq)
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
