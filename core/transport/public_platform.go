package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/flynn/noise"

	awgdialect "github.com/TrafficWrapper/worker/core/awg/dialect"
	"github.com/TrafficWrapper/worker/core/internal/provisionclient"
)

const (
	orchestratorNoisePrologue = "TrafficWrapper orchestrator worker v1"
	publicEnrollTimeout       = 35 * time.Second
)

type publicDeviceEnrollAPIRequest struct {
	OrchestratorURL string `json:"orchestrator_url"`
	OrchNoisePublic string `json:"orch_noise_public"`
	BootstrapToken  string `json:"bootstrap_token"`
	NoisePrivateKey string `json:"noise_private_key"`
	NoisePublicKey  string `json:"noise_public_key"`
	DeviceID        string `json:"device_id,omitempty"`
	AndroidID       string `json:"android_id,omitempty"`
	Model           string `json:"model,omitempty"`
	IdentityPubKey  string `json:"identity_pubkey"`
	IdentityKeyType string `json:"identity_key_type,omitempty"`
	EnrollmentNonce string `json:"enrollment_nonce,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
	TimeoutSeconds  int64  `json:"timeout_seconds,omitempty"`
}

type publicDeviceEnrollAPIResult struct {
	OK              bool            `json:"ok"`
	Error           string          `json:"error,omitempty"`
	DeviceID        string          `json:"device_id,omitempty"`
	Status          string          `json:"status,omitempty"`
	RealityUUID     string          `json:"reality_uuid,omitempty"`
	InternalIP      string          `json:"internal_ip,omitempty"`
	PSK2            string          `json:"psk2,omitempty"`
	ServerAWGPublic string          `json:"server_awg_public,omitempty"`
	SignerPublicKey string          `json:"signer_public_key,omitempty"`
	ClientBundle    json.RawMessage `json:"client_bundle,omitempty"`
	AWGPrivateKey   string          `json:"awg_private_key,omitempty"`
	AWGPublicKey    string          `json:"awg_public_key,omitempty"`
}

type publicDeviceEnrollWireRequest struct {
	BootstrapToken  string `json:"bootstrap_token"`
	NoisePublicKey  string `json:"noise_public_key,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	AndroidID       string `json:"android_id,omitempty"`
	Model           string `json:"model,omitempty"`
	IdentityPubKey  string `json:"identity_pubkey"`
	IdentityKeyType string `json:"identity_key_type,omitempty"`
	EnrollmentNonce string `json:"enrollment_nonce,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
	AWGPublicKey    string `json:"awg_public_key,omitempty"`
}

type publicDeviceEnrollWireResponse struct {
	OK              bool            `json:"ok"`
	Error           string          `json:"error,omitempty"`
	DeviceID        string          `json:"device_id,omitempty"`
	Status          string          `json:"status,omitempty"`
	RealityUUID     string          `json:"reality_uuid,omitempty"`
	InternalIP      string          `json:"internal_ip,omitempty"`
	PSK2            string          `json:"psk2,omitempty"`
	ServerAWGPublic string          `json:"server_awg_public,omitempty"`
	SignerPublicKey string          `json:"signer_public_key,omitempty"`
	ClientBundle    json.RawMessage `json:"client_bundle,omitempty"`
}

type publicNoiseStartRequest struct {
	Message string `json:"message"`
}

type publicNoiseStartResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	SID     string `json:"sid,omitempty"`
	Message string `json:"message,omitempty"`
}

type publicNoiseEnvelope struct {
	SID     string `json:"sid"`
	Message string `json:"message"`
	Payload string `json:"payload"`
}

type publicNoiseEnvelopeResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Payload string `json:"payload,omitempty"`
}

type publicApplyAPIRequest struct {
	AWGPrivateKey    string           `json:"awg_private_key"`
	InternalIP       string           `json:"internal_ip"`
	PSK2             string           `json:"psk2"`
	ServerAWGPublic  string           `json:"server_awg_public"`
	AWGRU            *publicRouteSpec `json:"awg_ru,omitempty"`
	AWG              *publicRouteSpec `json:"awg,omitempty"`
	AWGRUSOCKSListen string           `json:"awg_ru_socks_listen,omitempty"`
	SOCKSListen      string           `json:"socks_listen,omitempty"`
	MTU              int              `json:"mtu,omitempty"`
}

type publicApplyAPIResult struct {
	OK                bool   `json:"ok"`
	Error             string `json:"error,omitempty"`
	ConfigStored      bool   `json:"config_stored,omitempty"`
	AWGRUConfigStored bool   `json:"awg_ru_config_stored,omitempty"`
}

type publicRouteSpec struct {
	Type      string          `json:"type,omitempty"`
	Address   string          `json:"address,omitempty"`
	Port      int             `json:"port,omitempty"`
	Endpoint  string          `json:"endpoint,omitempty"`
	EgressIP  string          `json:"expected_egress_ip,omitempty"`
	PublicKey string          `json:"public_key,omitempty"`
	Dialect   json.RawMessage `json:"dialect,omitempty"`
	AWGPreset json.RawMessage `json:"awg_preset,omitempty"`
}

// PublicDeviceEnroll performs public-platform device enrollment over the
// orchestrator Noise_XK HTTP envelope. The TLS channel is only a carrier here:
// authenticity is the pinned orchestrator static key.
func PublicDeviceEnroll(requestJSON string) string {
	var req publicDeviceEnrollAPIRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return encodePublicDeviceEnrollResult(publicDeviceEnrollAPIResult{OK: false, Error: fmt.Sprintf("parse request json: %v", err)})
	}
	result, err := publicDeviceEnroll(req)
	if err != nil {
		return encodePublicDeviceEnrollResult(publicDeviceEnrollAPIResult{OK: false, Error: err.Error()})
	}
	return encodePublicDeviceEnrollResult(result)
}

func ApplyPublicPlatformConfig(requestJSON string) string {
	var req publicApplyAPIRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return encodePublicApplyResult(publicApplyAPIResult{OK: false, Error: fmt.Sprintf("parse request json: %v", err)})
	}
	result, err := applyPublicPlatformConfig(req)
	if err != nil {
		return encodePublicApplyResult(publicApplyAPIResult{OK: false, Error: err.Error()})
	}
	return encodePublicApplyResult(result)
}

func publicDeviceEnroll(req publicDeviceEnrollAPIRequest) (publicDeviceEnrollAPIResult, error) {
	if req.OrchestratorURL == "" || req.OrchNoisePublic == "" || req.BootstrapToken == "" ||
		req.NoisePrivateKey == "" || req.NoisePublicKey == "" || req.IdentityPubKey == "" {
		return publicDeviceEnrollAPIResult{}, errors.New("public enrollment request is incomplete")
	}
	awgPrivate, awgPublic, err := provisionclient.GenerateWireGuardKeyPair()
	if err != nil {
		return publicDeviceEnrollAPIResult{}, fmt.Errorf("generate awg keypair: %w", err)
	}
	timeout := publicEnrollTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var wireResp publicDeviceEnrollWireResponse
	err = publicNoiseJSONRequest(
		ctx,
		req.OrchestratorURL,
		req.OrchNoisePublic,
		req.NoisePrivateKey,
		req.NoisePublicKey,
		"/d/v1/enroll",
		publicDeviceEnrollWireRequest{
			BootstrapToken:  req.BootstrapToken,
			NoisePublicKey:  req.NoisePublicKey,
			DeviceID:        req.DeviceID,
			AndroidID:       req.AndroidID,
			Model:           req.Model,
			IdentityPubKey:  req.IdentityPubKey,
			IdentityKeyType: req.IdentityKeyType,
			EnrollmentNonce: req.EnrollmentNonce,
			ClientVersion:   req.ClientVersion,
			AWGPublicKey:    awgPublic,
		},
		&wireResp,
	)
	if err != nil {
		return publicDeviceEnrollAPIResult{}, err
	}
	if !wireResp.OK {
		return publicDeviceEnrollAPIResult{}, fmt.Errorf("public device enrollment rejected: %s", wireResp.Error)
	}
	return publicDeviceEnrollAPIResult{
		OK:              true,
		DeviceID:        wireResp.DeviceID,
		Status:          wireResp.Status,
		RealityUUID:     wireResp.RealityUUID,
		InternalIP:      wireResp.InternalIP,
		PSK2:            wireResp.PSK2,
		ServerAWGPublic: wireResp.ServerAWGPublic,
		SignerPublicKey: wireResp.SignerPublicKey,
		ClientBundle:    wireResp.ClientBundle,
		AWGPrivateKey:   awgPrivate,
		AWGPublicKey:    awgPublic,
	}, nil
}

func publicNoiseJSONRequest(ctx context.Context, baseURL, serverPublic, clientPrivate, clientPublic, path string, req any, resp any) error {
	serverPub, err := decodeKeyBase64(serverPublic)
	if err != nil {
		return fmt.Errorf("orchestrator static public key: %w", err)
	}
	clientStatic, err := provisionclient.LoadKeyPairFromBase64(clientPrivate, clientPublic)
	if err != nil {
		return fmt.Errorf("client noise keypair: %w", err)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		Prologue:      []byte(orchestratorNoisePrologue),
		StaticKeypair: clientStatic,
		PeerStatic:    serverPub,
	})
	if err != nil {
		return err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	client := publicHTTPClient()
	var start publicNoiseStartResponse
	if err := postJSON(ctx, client, joinPublicURL(baseURL, "/d/v1/handshake/start"), publicNoiseStartRequest{
		Message: base64.StdEncoding.EncodeToString(msg1),
	}, &start); err != nil {
		return err
	}
	if !start.OK {
		return errors.New(start.Error)
	}
	msg2, err := base64.StdEncoding.DecodeString(start.Message)
	if err != nil {
		return err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		return err
	}
	msg3, sendCipher, recvCipher, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(req)
	if err != nil {
		return err
	}
	payload, err := sendCipher.Encrypt(nil, nil, plain)
	if err != nil {
		return err
	}
	var envelope publicNoiseEnvelopeResponse
	if err := postJSON(ctx, client, joinPublicURL(baseURL, path), publicNoiseEnvelope{
		SID:     start.SID,
		Message: base64.StdEncoding.EncodeToString(msg3),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}, &envelope); err != nil {
		return err
	}
	if !envelope.OK {
		return errors.New(envelope.Error)
	}
	encrypted, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return err
	}
	decrypted, err := recvCipher.Decrypt(nil, nil, encrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal(decrypted, resp)
}

func publicHTTPClient() *http.Client {
	return &http.Client{
		Timeout: publicEnrollTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Noise pins the orchestrator static key.
		},
	}
}

func postJSON(ctx context.Context, client *http.Client, endpoint string, req any, resp any) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if httpResp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", httpResp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, resp); err != nil {
		return err
	}
	return nil
}

func joinPublicURL(base, path string) string {
	u, err := url.Parse(base)
	if err != nil {
		return strings.TrimRight(base, "/") + path
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String()
}

func applyPublicPlatformConfig(req publicApplyAPIRequest) (publicApplyAPIResult, error) {
	if req.AWGPrivateKey == "" || req.InternalIP == "" || req.PSK2 == "" || req.ServerAWGPublic == "" {
		return publicApplyAPIResult{}, errors.New("public awg credentials are incomplete")
	}
	if req.MTU == 0 {
		req.MTU = defaultMTU
	}
	if req.SOCKSListen == "" {
		req.SOCKSListen = defaultSOCKSListen
	}
	if req.AWGRUSOCKSListen == "" {
		req.AWGRUSOCKSListen = defaultAWGRUSOCKSListen
	}
	var defaultConfigJSON string
	if req.AWG != nil {
		raw, err := publicAWGConfigJSON(req.AWG, req, req.SOCKSListen)
		if err != nil {
			return publicApplyAPIResult{}, fmt.Errorf("public awg config: %w", err)
		}
		defaultConfigJSON = raw
	}
	var awgRUConfigJSON string
	if req.AWGRU != nil {
		raw, err := publicAWGConfigJSON(req.AWGRU, req, req.AWGRUSOCKSListen)
		if err != nil {
			return publicApplyAPIResult{}, fmt.Errorf("public awg-ru config: %w", err)
		}
		awgRUConfigJSON = raw
	}
	pendingProvision.Lock()
	pendingProvision.configJSON = defaultConfigJSON
	pendingProvision.awgRUConfigJSON = awgRUConfigJSON
	pendingProvision.Unlock()
	return publicApplyAPIResult{
		OK:                true,
		ConfigStored:      defaultConfigJSON != "",
		AWGRUConfigStored: awgRUConfigJSON != "",
	}, nil
}

func publicAWGConfigJSON(route *publicRouteSpec, req publicApplyAPIRequest, socksListen string) (string, error) {
	endpoint := strings.TrimSpace(route.Endpoint)
	if endpoint == "" && route.Address != "" && route.Port > 0 {
		endpoint = fmt.Sprintf("%s:%d", route.Address, route.Port)
	}
	endpoint = endpointUsingPinnedIP(endpoint, route.EgressIP)
	serverKey := strings.TrimSpace(route.PublicKey)
	if serverKey == "" {
		serverKey = req.ServerAWGPublic
	}
	presetValue, err := route.preset()
	if err != nil {
		return "", err
	}
	cfg := config{
		PrivateKey:      req.AWGPrivateKey,
		InternalIP:      req.InternalIP,
		Endpoint:        endpoint,
		ServerPublicKey: serverKey,
		PSK2:            req.PSK2,
		AWGPreset:       presetValue,
		SOCKSListen:     socksListen,
		MTU:             req.MTU,
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	if _, err := parseConfig(string(raw)); err != nil {
		return "", err
	}
	return string(raw), nil
}

func endpointUsingPinnedIP(endpoint string, ip string) string {
	endpoint = strings.TrimSpace(endpoint)
	ip = strings.TrimSpace(ip)
	if endpoint == "" || ip == "" {
		return endpoint
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return endpoint
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || port == "" {
		return endpoint
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return endpoint
	}
	return net.JoinHostPort(ip, port)
}

func (r *publicRouteSpec) preset() (preset, error) {
	raw := r.AWGPreset
	if len(raw) == 0 {
		raw = r.Dialect
	}
	if len(raw) == 0 || string(raw) == "null" {
		return awgdialect.Compat(), nil
	}
	var out preset
	if err := json.Unmarshal(raw, &out); err != nil {
		return preset{}, fmt.Errorf("awg dialect: %w", err)
	}
	return out, nil
}

func encodePublicDeviceEnrollResult(result publicDeviceEnrollAPIResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal public enroll result"}`
	}
	return string(raw)
}

func encodePublicApplyResult(result publicApplyAPIResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal public apply result"}`
	}
	return string(raw)
}
