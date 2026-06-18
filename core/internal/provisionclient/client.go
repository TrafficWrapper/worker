package provisionclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/flynn/noise"

	awgdialect "github.com/TrafficWrapper/worker/core/awg/dialect"
)

const (
	prologue     = "TrafficWrapper provisioning v1"
	keySize      = 32
	maxFrameSize = 1 << 20
)

type KeyPairFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type Preset = awgdialect.Dialect

type Request struct {
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

type Response struct {
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
	AWGPreset          Preset         `json:"awg_preset,omitempty"`
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
	AWGPreset       Preset    `json:"awg_preset,omitempty"`
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

type UpdateManifestResponse struct {
	OK                    bool      `json:"ok"`
	Error                 string    `json:"error,omitempty"`
	VersionJSON           string    `json:"version_json,omitempty"`
	VersionJSONMinisig    string    `json:"version_json_minisig,omitempty"`
	VersionJSONSHA256     string    `json:"version_json_sha256,omitempty"`
	ServerTime            time.Time `json:"server_time"`
	ServerTimeTrustedHint string    `json:"server_time_trusted_hint,omitempty"`
}

type Options struct {
	Addr               string
	ServerPublicKey    string
	IdentityKeyPath    string
	IdentityPrivateKey string
	IdentityPublicKey  string
	Username           string
	Secret             string
	SecretEnv          string
	SecretFile         string
}

type DeviceEnrollRequest struct {
	DeviceID            string
	AndroidID           string
	Model               string
	IdentityPubKey      string
	IdentityKeyType     string
	EnrollmentSecret    string
	EnrollmentSignature string
	EnrollmentNonce     string
	ClientVersion       string
	WGPublicKey         string
	AWGRUPublicKey      string
}

func GenerateWireGuardKeyPair() (privateB64, publicB64 string, err error) {
	return generateKeyPair()
}

func GenerateIdentityKeyPair() (privateB64, publicB64 string, err error) {
	return generateKeyPair()
}

func generateKeyPair() (privateB64, publicB64 string, err error) {
	key, err := cipherSuite().GenerateKeypair(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return encodeKey(key.Private), encodeKey(key.Public), nil
}

func Provision(ctx context.Context, opts Options, wgPublic string) (Response, error) {
	if opts.Addr == "" {
		return Response{}, errors.New("provision address not configured")
	}
	if opts.ServerPublicKey == "" || opts.Username == "" {
		return Response{}, errors.New("provision-server-public and username are required")
	}
	secret, err := readSecret(opts.Secret, opts.SecretEnv, opts.SecretFile)
	if err != nil {
		return Response{}, err
	}
	identity, err := loadIdentity(opts)
	if err != nil {
		return Response{}, err
	}
	serverPub, err := decodeKey(opts.ServerPublicKey)
	if err != nil {
		return Response{}, fmt.Errorf("provision server public key: %w", err)
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", opts.Addr)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	}
	sendCipher, recvCipher, err := noiseIK(conn, identity, serverPub)
	if err != nil {
		return Response{}, err
	}
	req := Request{Username: opts.Username, Secret: secret, WGPublicKey: wgPublic}
	if err := writeEncryptedJSON(conn, sendCipher, req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := readEncryptedJSON(conn, recvCipher, &resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		return Response{}, fmt.Errorf("provisioning rejected request: %s", resp.Error)
	}
	if resp.InternalIP == "" || resp.Endpoint == "" || resp.ServerPublicKey == "" || resp.PSK2 == "" {
		return Response{}, errors.New("provisioning response is incomplete")
	}
	return resp, nil
}

func DeviceEnroll(ctx context.Context, opts Options, enroll DeviceEnrollRequest) (Response, error) {
	if opts.Addr == "" {
		return Response{}, errors.New("provision address not configured")
	}
	if opts.ServerPublicKey == "" {
		return Response{}, errors.New("provision-server-public is required")
	}
	if enroll.DeviceID == "" || enroll.IdentityPubKey == "" || enroll.IdentityKeyType == "" ||
		enroll.EnrollmentSecret == "" || enroll.EnrollmentSignature == "" || enroll.EnrollmentNonce == "" {
		return Response{}, errors.New("device enrollment request is incomplete")
	}
	identity, err := loadIdentity(opts)
	if err != nil {
		return Response{}, err
	}
	serverPub, err := decodeKey(opts.ServerPublicKey)
	if err != nil {
		return Response{}, fmt.Errorf("provision server public key: %w", err)
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", opts.Addr)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	}
	sendCipher, recvCipher, err := noiseIK(conn, identity, serverPub)
	if err != nil {
		return Response{}, err
	}
	req := Request{
		Action:              "device_enroll",
		DeviceID:            enroll.DeviceID,
		AndroidID:           enroll.AndroidID,
		Model:               enroll.Model,
		IdentityPubKey:      enroll.IdentityPubKey,
		IdentityKeyType:     enroll.IdentityKeyType,
		EnrollmentSecret:    enroll.EnrollmentSecret,
		EnrollmentSignature: enroll.EnrollmentSignature,
		EnrollmentNonce:     enroll.EnrollmentNonce,
		ClientVersion:       enroll.ClientVersion,
		WGPublicKey:         enroll.WGPublicKey,
		AWGRUPublicKey:      enroll.AWGRUPublicKey,
	}
	if err := writeEncryptedJSON(conn, sendCipher, req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := readEncryptedJSON(conn, recvCipher, &resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		return Response{}, fmt.Errorf("device enrollment rejected: %s", resp.Error)
	}
	return resp, nil
}

func GetUpdateManifest(ctx context.Context, opts Options) (UpdateManifestResponse, error) {
	if opts.Addr == "" {
		return UpdateManifestResponse{}, errors.New("provision address not configured")
	}
	if opts.ServerPublicKey == "" || opts.Username == "" {
		return UpdateManifestResponse{}, errors.New("provision-server-public and username are required")
	}
	secret, err := readSecret(opts.Secret, opts.SecretEnv, opts.SecretFile)
	if err != nil {
		return UpdateManifestResponse{}, err
	}
	identity, err := loadIdentity(opts)
	if err != nil {
		return UpdateManifestResponse{}, err
	}
	serverPub, err := decodeKey(opts.ServerPublicKey)
	if err != nil {
		return UpdateManifestResponse{}, fmt.Errorf("provision server public key: %w", err)
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", opts.Addr)
	if err != nil {
		return UpdateManifestResponse{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	}
	sendCipher, recvCipher, err := noiseIK(conn, identity, serverPub)
	if err != nil {
		return UpdateManifestResponse{}, err
	}
	req := Request{
		Action:   "get_update_manifest",
		Username: opts.Username,
		Secret:   secret,
	}
	if err := writeEncryptedJSON(conn, sendCipher, req); err != nil {
		return UpdateManifestResponse{}, err
	}
	var resp UpdateManifestResponse
	if err := readEncryptedJSON(conn, recvCipher, &resp); err != nil {
		return UpdateManifestResponse{}, err
	}
	if !resp.OK {
		return UpdateManifestResponse{}, fmt.Errorf("update manifest rejected: %s", resp.Error)
	}
	if resp.VersionJSON == "" || resp.VersionJSONMinisig == "" {
		return UpdateManifestResponse{}, errors.New("update manifest response is incomplete")
	}
	return resp, nil
}

func LoadKeyPair(path string) (noise.DHKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return noise.DHKey{}, err
	}
	var file KeyPairFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return noise.DHKey{}, err
	}
	privateBytes, err := decodeKey(file.PrivateKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("private key: %w", err)
	}
	publicBytes, err := decodeKey(file.PublicKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("public key: %w", err)
	}
	return noise.DHKey{Private: privateBytes, Public: publicBytes}, nil
}

func LoadKeyPairFromBase64(privateKey, publicKey string) (noise.DHKey, error) {
	privateBytes, err := decodeKey(privateKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("private key: %w", err)
	}
	publicBytes, err := decodeKey(publicKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("public key: %w", err)
	}
	return noise.DHKey{Private: privateBytes, Public: publicBytes}, nil
}

func loadIdentity(opts Options) (noise.DHKey, error) {
	switch {
	case opts.IdentityPrivateKey != "" || opts.IdentityPublicKey != "":
		if opts.IdentityPrivateKey == "" || opts.IdentityPublicKey == "" {
			return noise.DHKey{}, errors.New("identity private and public keys must be provided together")
		}
		return LoadKeyPairFromBase64(opts.IdentityPrivateKey, opts.IdentityPublicKey)
	case opts.IdentityKeyPath != "":
		return LoadKeyPair(opts.IdentityKeyPath)
	default:
		return noise.DHKey{}, errors.New("identity key is required")
	}
}

func readSecret(value, envName, filePath string) (string, error) {
	switch {
	case value != "":
		return value, nil
	case envName != "":
		secret := os.Getenv(envName)
		if secret == "" {
			return "", fmt.Errorf("env %s is empty", envName)
		}
		return secret, nil
	case filePath != "":
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(raw), "\r\n"), nil
	default:
		return "", errors.New("secret must be provided by --secret, --secret-env or --secret-file")
	}
}

func noiseIK(conn net.Conn, identity noise.DHKey, serverPub []byte) (*noise.CipherState, *noise.CipherState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte(prologue),
		StaticKeypair: identity,
		PeerStatic:    serverPub,
	})
	if err != nil {
		return nil, nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(conn, msg1); err != nil {
		return nil, nil, err
	}
	msg2, err := readFrame(conn)
	if err != nil {
		return nil, nil, err
	}
	if _, sendCipher, recvCipher, err := hs.ReadMessage(nil, msg2); err != nil {
		return nil, nil, err
	} else {
		return sendCipher, recvCipher, nil
	}
}

func writeEncryptedJSON(w io.Writer, cipher *noise.CipherState, value any) error {
	plain, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encrypted, err := cipher.Encrypt(nil, nil, plain)
	if err != nil {
		return err
	}
	return writeFrame(w, encrypted)
}

func readEncryptedJSON(r io.Reader, cipher *noise.CipherState, value any) error {
	encrypted, err := readFrame(r)
	if err != nil {
		return err
	}
	plain, err := cipher.Decrypt(nil, nil, encrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, value)
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d", size)
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(r, payload)
	return payload, err
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

func decodeKey(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(raw) != keySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", keySize, len(raw))
	}
	return raw, nil
}

func encodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func cipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}
