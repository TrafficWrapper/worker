package serverpeer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/dialect"
)

// Registry is the peer registry file the agent writes and awg-gw restores
// peers from on startup.
type Registry struct {
	Clients []RegistryClient `json:"clients"`
}

// RegistryClient is one peer entry of Registry. Keys are standard base64.
type RegistryClient struct {
	WGPublicKey  string    `json:"wg_public_key"`
	InternalIP   string    `json:"internal_ip"`
	PSK2         string    `json:"psk2"`
	ExpiresAt    time.Time `json:"expires_at"`
	DownloadMbps int       `json:"download_mbps,omitempty"`
	UploadMbps   int       `json:"upload_mbps,omitempty"`
}

// GatewayConfig is the awg-gw config file rendered by the agent.
// server_keepalive has no omitempty: the agent always writes it, 0 included.
type GatewayConfig struct {
	Interface       string          `json:"interface"`
	Address         string          `json:"address"`
	ListenPort      int             `json:"listen_port"`
	PrivateKeyHex   string          `json:"private_key_hex"`
	PublicKey       string          `json:"public_key"`
	Dialect         dialect.Dialect `json:"dialect"`
	PeerRegistry    string          `json:"peer_registry,omitempty"`
	ServerKeepalive int             `json:"server_keepalive"`
}

// KeyB64ToHex converts a standard-base64 32-byte key to lowercase hex.
func KeyB64ToHex(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
