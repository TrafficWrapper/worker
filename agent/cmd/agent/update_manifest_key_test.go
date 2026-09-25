package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
)

// withUpdateKey publishes a client config naming pub as update_pubkey.
func withUpdateKey(t *testing.T, stateDir, pub string) {
	t.Helper()
	cfg := `{"schema":1,"update_pubkey":` + jsonString(pub) + `}`
	if err := writeFile(filepath.Join(stateDir, "distributor", "tw", "config.json"), []byte(cfg+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func jsonString(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "\n", `\n`) + `"`
}

func newUpdateKey(t *testing.T) (string, minisign.PrivateKey) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	text, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return string(text), priv
}

func signedAPKRef(t *testing.T, priv minisign.PrivateKey, apk []byte) orchUpdateRef {
	t.Helper()
	ref := testAPKRef(t, apk, "app.apk", time.Now().Add(time.Hour))
	ref.ManifestMinisig = string(minisign.Sign(priv, []byte(ref.ManifestJSON)))
	return ref
}

func TestUpdateManifestVerifiedWithUpdateKey(t *testing.T) {
	stateDir := t.TempDir()
	pub, priv := newUpdateKey(t)
	withUpdateKey(t, stateDir, pub)
	apk := testAPKBytes(3000)
	ref := signedAPKRef(t, priv, apk)
	if err := publishUpdateManifest(stateDir, ref.ManifestJSON, ref.ManifestMinisig); err != nil {
		t.Fatalf("correctly signed manifest rejected: %v", err)
	}
	// A whole .pub file with its comment line is accepted as well.
	withUpdateKey(t, stateDir, "untrusted comment: minisign public key\n"+pub+"\n")
	if err := checkUpdateManifestSignature(stateDir, ref.ManifestJSON, ref.ManifestMinisig); err != nil {
		t.Fatalf(".pub file form rejected: %v", err)
	}
}

func TestUpdateManifestWithWrongSignatureIsNotServed(t *testing.T) {
	stateDir := t.TempDir()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	pub, _ := newUpdateKey(t)
	withUpdateKey(t, stateDir, pub)
	_, otherPriv := newUpdateKey(t)
	apk := testAPKBytes(3000)
	ref := signedAPKRef(t, otherPriv, apk)

	if err := publishUpdateManifest(stateDir, ref.ManifestJSON, ref.ManifestMinisig); err == nil {
		t.Fatal("manifest signed by another key published")
	}
	// update_ref: nothing is downloaded.
	server := &fakeChunkServer{apk: apk}
	d := &apkDownloader{}
	d.handle(t.Context(), envConfig{StateDir: stateDir}, server, "w1", ref)
	d.wait()
	if len(server.requests) != 0 {
		t.Fatalf("apk with a bad manifest signature downloaded: %d requests", len(server.requests))
	}
	// Inline APK from an older orchestrator: nothing is written.
	err := writeUpdateArtifact(envConfig{StateDir: stateDir}, &orchUpdateArtifact{
		ManifestJSON: ref.ManifestJSON, ManifestMinisig: ref.ManifestMinisig,
		APKName: ref.APKName, APKSHA256: ref.APKSHA256, APKBase64: base64.StdEncoding.EncodeToString(apk),
	})
	if err == nil {
		t.Fatal("inline apk with a bad manifest signature accepted")
	}
	for _, name := range []string{"app.apk", "update-manifest.json", "update-manifest.json.minisig"} {
		if fileExists(filepath.Join(twDir, name)) {
			t.Fatalf("%s published", name)
		}
	}
}

func TestUpdateManifestUncheckedWithoutUsableKey(t *testing.T) {
	apk := testAPKBytes(3000)
	ref := testAPKRef(t, apk, "app.apk", time.Now().Add(time.Hour))
	for name, setup := range map[string]func(t *testing.T, stateDir string){
		"no client config": func(*testing.T, string) {},
		"no update_pubkey": func(t *testing.T, stateDir string) {
			if err := writeFile(filepath.Join(stateDir, "distributor", "tw", "config.json"), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"unreadable key": func(t *testing.T, stateDir string) { withUpdateKey(t, stateDir, "not a key") },
	} {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			setup(t, stateDir)
			if err := publishUpdateManifest(stateDir, ref.ManifestJSON, ref.ManifestMinisig); err != nil {
				t.Fatalf("manifest not published as before: %v", err)
			}
			if _, err := os.Stat(filepath.Join(stateDir, "distributor", "tw", "update-manifest.json")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
