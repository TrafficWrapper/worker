package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/TrafficWrapper/worker/agent/internal/protocol"
	"github.com/TrafficWrapper/worker/core/awg/dialect"
)

type stateFile struct {
	CreatedAt       time.Time            `json:"created_at"`
	Hostname        string               `json:"hostname"`
	EgressIP        string               `json:"egress_ip"`
	Reality         realityState         `json:"reality"`
	AWG             awgState             `json:"awg"`
	Dialect         dialect.Dialect      `json:"dialect"`
	DialectID       string               `json:"dialect_id"`
	NoiseStatic     protocol.KeyPairFile `json:"noise_static"`
	EnrollTokenHash string               `json:"enroll_token_hash,omitempty"`
	// ProfileDialects holds dialects of AWG profiles with own_dialect, keyed
	// by profile name.
	ProfileDialects  map[string]dialect.Dialect `json:"profile_dialects,omitempty"`
	SmokeRealityUUID string                     `json:"smoke_reality_uuid"`
}

type realityState struct {
	PrivateKey     string   `json:"private_key"`
	PublicKey      string   `json:"public_key"`
	ShortID        string   `json:"short_id"`
	CohortShortIDs []string `json:"cohort_short_ids,omitempty"`
}

type awgState struct {
	PrivateKeyHex string `json:"private_key_hex"`
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	SmokePrivate  string `json:"smoke_private_key"`
	SmokePublic   string `json:"smoke_public_key"`
	SmokePSK      string `json:"smoke_psk"`
	SmokeIP       string `json:"smoke_ip"`
}

func bootstrap(cfg envConfig) (stateFile, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return stateFile{}, err
	}
	path := filepath.Join(cfg.StateDir, "bootstrap.json")
	if raw, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(raw))) == 0 {
		// An empty file holds no keys to keep; starting over beats a
		// crash loop on "parse bootstrap state".
		slog.Warn("bootstrap state is empty; generating a new one", "path", path)
		if err := os.Remove(path); err != nil {
			return stateFile{}, err
		}
	}
	if raw, err := os.ReadFile(path); err == nil {
		var st stateFile
		if err := json.Unmarshal(raw, &st); err != nil {
			return stateFile{}, fmt.Errorf("parse bootstrap state: %w", err)
		}
		var err error
		st, err = reconcileBootstrapEgress(path, cfg, st)
		if err != nil {
			return stateFile{}, err
		}
		changed, err := ensureProfileDialects(cfg, &st)
		if err != nil {
			return stateFile{}, err
		}
		if ensureRealityCohorts(&st) || changed {
			if err := writeJSONFile(path, st, 0o600); err != nil {
				return stateFile{}, err
			}
		}
		if err := renderAll(cfg, st); err != nil {
			return stateFile{}, err
		}
		return st, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return stateFile{}, err
	}

	d, err := workerDialect()
	if err != nil {
		return stateFile{}, err
	}
	dialectID, err := dialectHash(d)
	if err != nil {
		return stateFile{}, err
	}
	realityPrivate, realityPublic, err := x25519RawURLEncoded()
	if err != nil {
		return stateFile{}, err
	}
	awgPrivateHex, awgPrivate, awgPublic, err := wgKeypair()
	if err != nil {
		return stateFile{}, err
	}
	smokePrivateHex, smokePrivate, smokePublic, err := wgKeypair()
	if err != nil {
		return stateFile{}, err
	}
	_ = smokePrivateHex
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return stateFile{}, err
	}
	noiseKey, err := protocol.GenerateKeypair()
	if err != nil {
		return stateFile{}, err
	}
	enrollHash := ""
	if cfg.EnrollToken != "" {
		enrollHash, err = protocol.HashSecret(cfg.EnrollToken)
		if err != nil {
			return stateFile{}, err
		}
	}
	host, _ := os.Hostname()
	st := stateFile{
		CreatedAt: time.Now().UTC(),
		Hostname:  host,
		EgressIP:  cfg.EgressIP,
		Reality: realityState{
			PrivateKey: realityPrivate,
			PublicKey:  realityPublic,
			ShortID:    randHex(8),
		},
		AWG: awgState{
			PrivateKeyHex: awgPrivateHex,
			PrivateKey:    awgPrivate,
			PublicKey:     awgPublic,
			SmokePrivate:  smokePrivate,
			SmokePublic:   smokePublic,
			SmokePSK:      base64.StdEncoding.EncodeToString(psk),
			SmokeIP:       secondHostCIDR(cfg.AWGSubnet),
		},
		Dialect:          d,
		DialectID:        dialectID,
		NoiseStatic:      protocol.NewKeyPairFile(noiseKey),
		EnrollTokenHash:  enrollHash,
		SmokeRealityUUID: uuidV4(),
	}
	ensureRealityCohorts(&st)
	if _, err := ensureProfileDialects(cfg, &st); err != nil {
		return stateFile{}, err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return stateFile{}, err
	}
	if err := createFileExclusive(path, append(raw, '\n'), 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			return bootstrap(cfg)
		}
		return stateFile{}, err
	}
	if err := renderAll(cfg, st); err != nil {
		return stateFile{}, err
	}
	return st, nil
}

func reconcileBootstrapEgress(path string, cfg envConfig, st stateFile) (stateFile, error) {
	if cfg.EgressIP == "" || st.EgressIP == cfg.EgressIP {
		return st, nil
	}
	st.EgressIP = cfg.EgressIP
	if err := writeJSONFile(path, st, 0o600); err != nil {
		return stateFile{}, err
	}
	return st, nil
}

func loadBootstrapState(stateDir string) (stateFile, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "bootstrap.json"))
	if err != nil {
		return stateFile{}, err
	}
	var st stateFile
	if err := json.Unmarshal(raw, &st); err != nil {
		return stateFile{}, fmt.Errorf("parse bootstrap state: %w", err)
	}
	return st, nil
}

func workerDialect() (dialect.Dialect, error) {
	if raw := strings.TrimSpace(os.Getenv("TW_WORKER_DIALECT_JSON")); raw != "" {
		var d dialect.Dialect
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			return dialect.Dialect{}, fmt.Errorf("parse TW_WORKER_DIALECT_JSON: %w", err)
		}
		if dialect.IsCompat(d) {
			return dialect.Dialect{}, errors.New("refusing example/compat AWG dialect")
		}
		if err := dialect.ValidateProduction(d, dialect.DefaultMTU); err != nil {
			return dialect.Dialect{}, err
		}
		return d, nil
	}
	d, err := generateDialect()
	if err != nil {
		return dialect.Dialect{}, err
	}
	if dialect.IsCompat(d) {
		return dialect.Dialect{}, errors.New("refusing generated compat AWG dialect")
	}
	return d, nil
}

func checkDialectFromEnv() error {
	_, err := workerDialect()
	return err
}

func wgKeypair() (privateHex, privateB64, publicB64 string, err error) {
	priv := make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return "", "", "", err
	}
	clamp(priv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", "", err
	}
	return hex.EncodeToString(priv), base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

func x25519RawURLEncoded() (privateKey, publicKey string, err error) {
	priv := make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return "", "", err
	}
	clamp(priv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv), base64.RawURLEncoding.EncodeToString(pub), nil
}

func clamp(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

func dialectHash(d dialect.Dialect) (string, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:12]), nil
}

func sha256HexBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func uuidV4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// generateDialect uses the wide junk-packet ranges only when the operator
// confirms every client accepts them (WORKER_DIALECT_WIDE=1).
func generateDialect() (dialect.Dialect, error) {
	if getenv("WORKER_DIALECT_WIDE", "0") == "1" {
		return dialect.GenerateWide()
	}
	return dialect.Generate()
}

func ensureProfileDialects(cfg envConfig, st *stateFile) (bool, error) {
	changed := false
	for _, profile := range awgProfiles(cfg) {
		if !profile.OwnDialect || profile.isBase() {
			continue
		}
		if _, ok := st.ProfileDialects[profile.Name]; ok {
			continue
		}
		d, err := generateDialect()
		if err != nil {
			return false, err
		}
		if st.ProfileDialects == nil {
			st.ProfileDialects = map[string]dialect.Dialect{}
		}
		st.ProfileDialects[profile.Name] = d
		changed = true
	}
	return changed, nil
}

func profileDialect(st stateFile, profile awgInboundProfile) dialect.Dialect {
	if d, ok := st.ProfileDialects[profile.Name]; ok && profile.OwnDialect {
		return d
	}
	return st.Dialect
}

func profileDialectID(st stateFile, profile awgInboundProfile) string {
	if d, ok := st.ProfileDialects[profile.Name]; ok && profile.OwnDialect {
		if id, err := dialectHash(d); err == nil {
			return id
		}
	}
	return st.DialectID
}
