package protocol

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/pbkdf2"

	awgdialect "github.com/TrafficWrapper/worker/core/awg/dialect"
)

const (
	Prologue     = "TrafficWrapper provisioning v1"
	MaxFrameSize = 1 << 20
	KeySize      = 32

	ActionProvision         = "provision"
	ActionGetUpdateManifest = "get_update_manifest"
	ActionDeviceEnroll      = "device_enroll"

	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusBlocked  = "blocked"

	DeviceIdentityEd25519     = "ed25519"
	DeviceIdentityECDSAP256   = "ecdsa-p256-sha256"
	deviceEnrollmentSignature = "TrafficWrapper device enrollment v1"

	TransportPreferenceAuto     = "AUTO"
	TransportPreferenceAWGRU    = "AWG_RU"
	TransportPreferenceAWG      = "AWG"
	TransportPreferenceReality  = "REALITY"
	TransportPreferenceReality2 = "REALITY2"
)

type Dialect = awgdialect.Dialect

type ProvisionRequest struct {
	Action              string `json:"action,omitempty"`
	Username            string `json:"username,omitempty"`
	Secret              string `json:"secret,omitempty"`
	WGPublicKey         string `json:"wg_public_key,omitempty"`
	DeviceID            string `json:"device_id,omitempty"`
	AndroidID           string `json:"android_id,omitempty"`
	Model               string `json:"model,omitempty"`
	IdentityPubKey      string `json:"identity_pubkey,omitempty"`
	IdentityKeyType     string `json:"identity_key_type,omitempty"`
	EnrollmentSecret    string `json:"enrollment_secret,omitempty"`
	EnrollmentSignature string `json:"enrollment_signature,omitempty"`
	EnrollmentNonce     string `json:"enrollment_nonce,omitempty"`
	ClientVersion       string `json:"client_version,omitempty"`
	AWGRUPublicKey      string `json:"awg_ru_public_key,omitempty"`
}

type ProvisionResponse struct {
	OK                 bool           `json:"ok"`
	Error              string         `json:"error,omitempty"`
	Status             string         `json:"status,omitempty"`
	DeviceID           string         `json:"device_id,omitempty"`
	Alias              string         `json:"alias,omitempty"`
	Message            string         `json:"message,omitempty"`
	InternalIP         string         `json:"internal_ip,omitempty"`
	Endpoint           string         `json:"endpoint,omitempty"`
	ServerPublicKey    string         `json:"server_public_key,omitempty"`
	PSK2               string         `json:"psk2,omitempty"`
	AWGPreset          Dialect        `json:"awg_preset,omitempty"`
	AWGRU              *AWGPeerConfig `json:"awg_ru,omitempty"`
	Reality            *RealityConfig `json:"reality,omitempty"`
	Reality2           *RealityConfig `json:"reality2,omitempty"`
	PreferredTransport string         `json:"preferred_transport,omitempty"`
	TTL                int64          `json:"ttl,omitempty"`
	ExpiresAt          time.Time      `json:"expires_at,omitempty"`
}

type AWGPeerConfig struct {
	InternalIP      string    `json:"internal_ip,omitempty"`
	Endpoint        string    `json:"endpoint,omitempty"`
	ServerPublicKey string    `json:"server_public_key,omitempty"`
	PSK2            string    `json:"psk2,omitempty"`
	AWGPreset       Dialect   `json:"awg_preset,omitempty"`
	TTL             int64     `json:"ttl,omitempty"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
}

type RealityConfig struct {
	Transport   string `json:"transport"`
	Address     string `json:"address"`
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	UUID        string `json:"uuid"`
	Email       string `json:"email,omitempty"`
	Flow        string `json:"flow"`
	Security    string `json:"security"`
	Network     string `json:"network"`
	ServerName  string `json:"serverName"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	Fingerprint string `json:"fingerprint"`
	SpiderX     string `json:"spiderX"`
	Dest        string `json:"dest,omitempty"`
}

type DeviceEnrollmentPayload struct {
	DeviceID        string
	AndroidID       string
	Model           string
	IdentityPubKey  string
	IdentityKeyType string
	Nonce           string
}

type UpdateManifestResponse struct {
	OK                    bool      `json:"ok"`
	Error                 string    `json:"error,omitempty"`
	VersionJSON           string    `json:"version_json,omitempty"`
	VersionJSONMinisig    string    `json:"version_json_minisig,omitempty"`
	VersionJSONSHA256     string    `json:"version_json_sha256,omitempty"`
	ServerTime            time.Time `json:"server_time"`
	ServerTimeTrustedHint string    `json:"server_time_trusted_hint,omitempty"`
}

type KeyPairFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func CipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

func GenerateKeypair() (noise.DHKey, error) {
	return CipherSuite().GenerateKeypair(rand.Reader)
}

func NewKeyPairFile(key noise.DHKey) KeyPairFile {
	return KeyPairFile{
		PrivateKey: KeyToBase64(key.Private),
		PublicKey:  KeyToBase64(key.Public),
	}
}

func DecodeKeyPair(privateKey, publicKey string) (noise.DHKey, error) {
	privateBytes, err := DecodeKeyBase64(privateKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("private key: %w", err)
	}
	publicBytes, err := DecodeKeyBase64(publicKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("public key: %w", err)
	}
	return noise.DHKey{Private: privateBytes, Public: publicBytes}, nil
}

func KeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func DecodeKeyBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(raw) != KeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", KeySize, len(raw))
	}
	return raw, nil
}

func Base64KeyToHex(value string) (string, error) {
	raw, err := DecodeKeyBase64(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func BytesToHexKey(value []byte) (string, error) {
	if len(value) != KeySize {
		return "", fmt.Errorf("expected %d bytes, got %d", KeySize, len(value))
	}
	return hex.EncodeToString(value), nil
}

func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func writeFull(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxFrameSize {
		return nil, fmt.Errorf("frame too large: %d", size)
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func WriteEncryptedJSON(w io.Writer, cipher *noise.CipherState, value any) error {
	plain, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encrypted, err := cipher.Encrypt(nil, nil, plain)
	if err != nil {
		return err
	}
	return WriteFrame(w, encrypted)
}

func ReadEncryptedJSON(r io.Reader, cipher *noise.CipherState, value any) error {
	encrypted, err := ReadFrame(r)
	if err != nil {
		return err
	}
	plain, err := cipher.Decrypt(nil, nil, encrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, value)
}

func EncryptJSON(cipher *noise.CipherState, value any) ([]byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(nil, nil, plain)
}

func DecryptJSON(cipher *noise.CipherState, encrypted []byte, value any) error {
	plain, err := cipher.Decrypt(nil, nil, encrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, value)
}

func HashSecret(secret string) (string, error) {
	if secret == "" {
		return "", errors.New("secret is empty")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const iterations = 150000
	key := pbkdf2.Key([]byte(secret), salt, iterations, KeySize, sha256.New)
	return fmt.Sprintf(
		"pbkdf2-sha256:%d:%s:%s",
		iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(key),
	), nil
}

func VerifySecret(encoded, secret string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || secret == "" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 10000 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) != KeySize {
		return false
	}
	actual := pbkdf2.Key([]byte(secret), salt, iterations, len(expected), sha256.New)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func ValidateDialect(d Dialect, mtu int) error {
	return awgdialect.Validate(d, mtu)
}

func DeviceEnrollmentPayloadFromRequest(req ProvisionRequest) DeviceEnrollmentPayload {
	return DeviceEnrollmentPayload{
		DeviceID:        strings.TrimSpace(req.DeviceID),
		AndroidID:       strings.TrimSpace(req.AndroidID),
		Model:           strings.TrimSpace(req.Model),
		IdentityPubKey:  strings.TrimSpace(req.IdentityPubKey),
		IdentityKeyType: strings.TrimSpace(req.IdentityKeyType),
		Nonce:           strings.TrimSpace(req.EnrollmentNonce),
	}
}

func (p DeviceEnrollmentPayload) CanonicalString() string {
	fields := []string{
		deviceEnrollmentSignature,
		p.DeviceID,
		p.AndroidID,
		p.Model,
		p.IdentityKeyType,
		p.IdentityPubKey,
		p.Nonce,
	}
	return strings.Join(fields, "\n")
}

func VerifyDeviceEnrollmentSignature(req ProvisionRequest) error {
	payload := DeviceEnrollmentPayloadFromRequest(req)
	if payload.DeviceID == "" {
		return errors.New("device_id is required")
	}
	if payload.IdentityPubKey == "" {
		return errors.New("identity_pubkey is required")
	}
	if payload.IdentityKeyType == "" {
		return errors.New("identity_key_type is required")
	}
	if payload.Nonce == "" {
		return errors.New("enrollment_nonce is required")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.EnrollmentSignature))
	if err != nil || len(signature) == 0 {
		return errors.New("enrollment_signature is invalid")
	}
	message := []byte(payload.CanonicalString())
	switch payload.IdentityKeyType {
	case DeviceIdentityEd25519:
		pub, err := base64.StdEncoding.DecodeString(payload.IdentityPubKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return errors.New("ed25519 identity_pubkey is invalid")
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), message, signature) {
			return errors.New("enrollment signature mismatch")
		}
		return nil
	case DeviceIdentityECDSAP256:
		pubRaw, err := base64.StdEncoding.DecodeString(payload.IdentityPubKey)
		if err != nil {
			return errors.New("ecdsa identity_pubkey is invalid")
		}
		pubAny, err := x509.ParsePKIXPublicKey(pubRaw)
		if err != nil {
			return errors.New("ecdsa identity_pubkey is not PKIX")
		}
		pub, ok := pubAny.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return errors.New("ecdsa identity_pubkey must be P-256")
		}
		sum := sha256.Sum256(message)
		r, s, ok := parseECDSASignature(signature)
		if !ok || !ecdsa.Verify(pub, sum[:], r, s) {
			return errors.New("enrollment signature mismatch")
		}
		return nil
	default:
		return fmt.Errorf("unsupported identity_key_type %q", payload.IdentityKeyType)
	}
}

func parseECDSASignature(signature []byte) (*big.Int, *big.Int, bool) {
	var der struct {
		R *big.Int
		S *big.Int
	}
	if rest, err := asn1.Unmarshal(signature, &der); err == nil && len(rest) == 0 && der.R != nil && der.S != nil {
		return der.R, der.S, true
	}
	if len(signature) == 64 {
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		return r, s, true
	}
	return nil, nil, false
}
