package main

import (
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

func mustMarshalText(t *testing.T, v interface{ MarshalText() ([]byte, error) }) string {
	t.Helper()
	raw, err := v.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
