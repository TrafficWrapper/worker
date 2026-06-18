package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TrafficWrapper/worker/core/internal/provisionclient"
)

const (
	defaultProvisionAddr = ""
	provisionTimeout     = 35 * time.Second
)

var pendingProvision struct {
	sync.Mutex
	configJSON      string
	awgRUConfigJSON string
}

type identityAPIResult struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
}

type deviceEnrollAPIRequest struct {
	Addr                    string `json:"provision_addr,omitempty"`
	ServerPublicKey         string `json:"provision_server_public"`
	NoisePrivateKey         string `json:"noise_private_key"`
	NoisePublicKey          string `json:"noise_public_key"`
	DeviceID                string `json:"device_id"`
	AndroidID               string `json:"android_id,omitempty"`
	Model                   string `json:"model,omitempty"`
	IdentityPubKey          string `json:"identity_pubkey"`
	IdentityKeyType         string `json:"identity_key_type"`
	EnrollmentSecret        string `json:"enrollment_secret"`
	EnrollmentSignature     string `json:"enrollment_signature"`
	EnrollmentNonce         string `json:"enrollment_nonce"`
	ClientVersion           string `json:"client_version,omitempty"`
	RequestKeys             bool   `json:"request_keys,omitempty"`
	SOCKSListen             string `json:"socks_listen,omitempty"`
	AWGRUSOCKSListen        string `json:"awg_ru_socks_listen,omitempty"`
	MTU                     int    `json:"mtu,omitempty"`
	TimeoutSeconds          int64  `json:"timeout_seconds,omitempty"`
	ExpectedServerAWGKey    string `json:"expected_server_awg_public,omitempty"`
	RequireExpectedAWGKey   bool   `json:"require_expected_awg_public,omitempty"`
	ExpectedServerAWGRUKey  string `json:"expected_server_awg_ru_public,omitempty"`
	RequireExpectedAWGRUKey bool   `json:"require_expected_awg_ru_public,omitempty"`
}

type provisionAPIResult struct {
	OK                 bool                           `json:"ok"`
	Error              string                         `json:"error,omitempty"`
	Status             string                         `json:"status,omitempty"`
	DeviceID           string                         `json:"device_id,omitempty"`
	Alias              string                         `json:"alias,omitempty"`
	Message            string                         `json:"message,omitempty"`
	ConfigStored       bool                           `json:"config_stored,omitempty"`
	InternalIP         string                         `json:"internal_ip,omitempty"`
	Endpoint           string                         `json:"endpoint,omitempty"`
	ServerPublicKey    string                         `json:"server_public_key,omitempty"`
	AWGRU              *provisionclient.AWGPeerConfig `json:"awg_ru,omitempty"`
	Reality            *provisionclient.RealityConfig `json:"reality,omitempty"`
	Reality2           *provisionclient.RealityConfig `json:"reality2,omitempty"`
	PreferredTransport string                         `json:"preferred_transport,omitempty"`
	TTL                int64                          `json:"ttl,omitempty"`
	ExpiresAt          time.Time                      `json:"expires_at,omitempty"`
	SOCKSListen        string                         `json:"socks_listen,omitempty"`
	IdentityPublicKey  string                         `json:"identity_public_key,omitempty"`
	WGPublicKey        string                         `json:"wg_public_key,omitempty"`
	AWGRUPublicKey     string                         `json:"awg_ru_public_key,omitempty"`
	WGPrivateKeySent   bool                           `json:"wg_private_key_sent"`
	WorkingKeysInGoRAM bool                           `json:"working_keys_in_go_ram,omitempty"`
	AWGRUConfigStored  bool                           `json:"awg_ru_config_stored,omitempty"`
}

// GenerateIdentity returns a fresh Noise_IK identity keypair for the platform
// layer to seal with Android Keystore before first use.
func GenerateIdentity() string {
	privateKey, publicKey, err := provisionclient.GenerateIdentityKeyPair()
	if err != nil {
		return encodeIdentityResult(identityAPIResult{OK: false, Error: err.Error()})
	}
	return encodeIdentityResult(identityAPIResult{OK: true, PrivateKey: privateKey, PublicKey: publicKey})
}

func DeviceEnroll(requestJSON string) string {
	var req deviceEnrollAPIRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return encodeProvisionResult(provisionAPIResult{OK: false, Error: fmt.Sprintf("parse request json: %v", err)})
	}
	result, err := deviceEnroll(req)
	if err != nil {
		return encodeProvisionResult(provisionAPIResult{OK: false, Error: err.Error()})
	}
	return encodeProvisionResult(result)
}

func StartProvisioned() string {
	pendingProvision.Lock()
	configJSON := pendingProvision.configJSON
	pendingProvision.Unlock()
	if configJSON == "" {
		return encodeResult(apiResult{OK: false, Error: "provisioned config is missing"})
	}
	return Start(configJSON)
}

func StartProvisionedAWGRU() string {
	pendingProvision.Lock()
	configJSON := pendingProvision.awgRUConfigJSON
	pendingProvision.Unlock()
	if configJSON == "" {
		return encodeResult(apiResult{OK: false, Error: "provisioned awg-ru config is missing"})
	}
	return StartNamed("awg_ru", configJSON)
}

func deviceEnroll(req deviceEnrollAPIRequest) (provisionAPIResult, error) {
	if req.Addr == "" {
		req.Addr = defaultProvisionAddr
	}
	if req.Addr == "" {
		return provisionAPIResult{}, errors.New("provision address not configured")
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
	if req.ServerPublicKey == "" || req.NoisePrivateKey == "" || req.NoisePublicKey == "" ||
		req.DeviceID == "" || req.IdentityPubKey == "" || req.IdentityKeyType == "" ||
		req.EnrollmentSecret == "" || req.EnrollmentSignature == "" || req.EnrollmentNonce == "" {
		return provisionAPIResult{}, errors.New("device enrollment request is incomplete")
	}

	wgPrivate := ""
	wgPublic := ""
	awgRUPrivate := ""
	awgRUPublic := ""
	var err error
	if req.RequestKeys {
		wgPrivate, wgPublic, err = provisionclient.GenerateWireGuardKeyPair()
		if err != nil {
			return provisionAPIResult{}, fmt.Errorf("generate wg keypair: %w", err)
		}
		awgRUPrivate, awgRUPublic, err = provisionclient.GenerateWireGuardKeyPair()
		if err != nil {
			return provisionAPIResult{}, fmt.Errorf("generate awg-ru keypair: %w", err)
		}
	}
	timeout := provisionTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := provisionclient.DeviceEnroll(ctx, provisionclient.Options{
		Addr:               req.Addr,
		ServerPublicKey:    req.ServerPublicKey,
		IdentityPrivateKey: req.NoisePrivateKey,
		IdentityPublicKey:  req.NoisePublicKey,
	}, provisionclient.DeviceEnrollRequest{
		DeviceID:            req.DeviceID,
		AndroidID:           req.AndroidID,
		Model:               req.Model,
		IdentityPubKey:      req.IdentityPubKey,
		IdentityKeyType:     req.IdentityKeyType,
		EnrollmentSecret:    req.EnrollmentSecret,
		EnrollmentSignature: req.EnrollmentSignature,
		EnrollmentNonce:     req.EnrollmentNonce,
		ClientVersion:       req.ClientVersion,
		WGPublicKey:         wgPublic,
		AWGRUPublicKey:      awgRUPublic,
	})
	if err != nil {
		return provisionAPIResult{}, err
	}
	result := provisionAPIResult{
		OK:                 true,
		Status:             resp.Status,
		DeviceID:           resp.DeviceID,
		Alias:              resp.Alias,
		Message:            resp.Message,
		InternalIP:         resp.InternalIP,
		Endpoint:           resp.Endpoint,
		ServerPublicKey:    resp.ServerPublicKey,
		AWGRU:              publicAWGRUConfig(resp.AWGRU),
		Reality:            resp.Reality,
		Reality2:           resp.Reality2,
		PreferredTransport: resp.PreferredTransport,
		TTL:                resp.TTL,
		ExpiresAt:          resp.ExpiresAt,
		SOCKSListen:        req.SOCKSListen,
		IdentityPublicKey:  req.IdentityPubKey,
		WGPublicKey:        wgPublic,
		AWGRUPublicKey:     awgRUPublic,
		WGPrivateKeySent:   false,
		WorkingKeysInGoRAM: false,
	}
	if resp.Status != "approved" || resp.InternalIP == "" || resp.Endpoint == "" || resp.ServerPublicKey == "" || resp.PSK2 == "" {
		return result, nil
	}
	if req.ExpectedServerAWGKey != "" && resp.ServerPublicKey != req.ExpectedServerAWGKey {
		if req.RequireExpectedAWGKey {
			return provisionAPIResult{}, errors.New("server awg public key mismatch")
		}
	}
	if req.RequireExpectedAWGRUKey && resp.AWGRU == nil {
		return provisionAPIResult{}, errors.New("server awg-ru config missing")
	}
	if req.ExpectedServerAWGRUKey != "" && resp.AWGRU != nil && resp.AWGRU.ServerPublicKey != req.ExpectedServerAWGRUKey {
		if req.RequireExpectedAWGRUKey {
			return provisionAPIResult{}, errors.New("server awg-ru public key mismatch")
		}
	}
	if wgPrivate == "" {
		return provisionAPIResult{}, errors.New("approved device response requires request_keys")
	}
	cfg := config{
		PrivateKey:      wgPrivate,
		InternalIP:      resp.InternalIP,
		Endpoint:        resp.Endpoint,
		ServerPublicKey: resp.ServerPublicKey,
		PSK2:            resp.PSK2,
		AWGPreset:       preset(resp.AWGPreset),
		SOCKSListen:     req.SOCKSListen,
		MTU:             req.MTU,
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return provisionAPIResult{}, err
	}
	if _, err := parseConfig(string(raw)); err != nil {
		return provisionAPIResult{}, err
	}
	pendingProvision.Lock()
	pendingProvision.configJSON = string(raw)
	pendingProvision.awgRUConfigJSON = ""
	pendingProvision.Unlock()
	result.ConfigStored = true
	result.WorkingKeysInGoRAM = true
	if resp.AWGRU != nil && resp.AWGRU.InternalIP != "" && resp.AWGRU.Endpoint != "" && resp.AWGRU.ServerPublicKey != "" && resp.AWGRU.PSK2 != "" {
		if awgRUPrivate == "" {
			return provisionAPIResult{}, errors.New("approved awg-ru response requires request_keys")
		}
		cfg := config{
			PrivateKey:      awgRUPrivate,
			InternalIP:      resp.AWGRU.InternalIP,
			Endpoint:        resp.AWGRU.Endpoint,
			ServerPublicKey: resp.AWGRU.ServerPublicKey,
			PSK2:            resp.AWGRU.PSK2,
			AWGPreset:       preset(resp.AWGRU.AWGPreset),
			SOCKSListen:     req.AWGRUSOCKSListen,
			MTU:             req.MTU,
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			return provisionAPIResult{}, err
		}
		if _, err := parseConfig(string(raw)); err != nil {
			return provisionAPIResult{}, err
		}
		pendingProvision.Lock()
		pendingProvision.awgRUConfigJSON = string(raw)
		pendingProvision.Unlock()
		result.AWGRUConfigStored = true
	}
	return result, nil
}

func publicAWGRUConfig(cfg *provisionclient.AWGPeerConfig) *provisionclient.AWGPeerConfig {
	if cfg == nil {
		return nil
	}
	out := *cfg
	out.PSK2 = ""
	return &out
}

func encodeIdentityResult(result identityAPIResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal identity"}`
	}
	return string(raw)
}

func encodeProvisionResult(result provisionAPIResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal provision result"}`
	}
	return string(raw)
}
