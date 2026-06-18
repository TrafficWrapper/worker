package transport

import (
	"encoding/json"
	"errors"
	"fmt"

	"aead.dev/minisign"
)

type minisignVerifyResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func VerifyMinisign(message string, signature string, publicKey string) string {
	if err := verifyMinisign(message, signature, publicKey); err != nil {
		return encodeMinisignVerifyResult(minisignVerifyResult{OK: false, Error: err.Error()})
	}
	return encodeMinisignVerifyResult(minisignVerifyResult{OK: true})
}

func verifyMinisign(message string, signature string, publicKey string) error {
	var pub minisign.PublicKey
	if err := pub.UnmarshalText([]byte(publicKey)); err != nil {
		return errors.New("invalid public key")
	}
	if !minisign.Verify(pub, []byte(message), []byte(signature)) {
		return errors.New("invalid signature")
	}
	return nil
}

func verifyMinisignResult(message string, signature string, publicKey string) error {
	if err := verifyMinisign(message, signature, publicKey); err != nil {
		return fmt.Errorf("verify minisign: %w", err)
	}
	return nil
}

func encodeMinisignVerifyResult(result minisignVerifyResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal minisign verify result"}`
	}
	return string(raw)
}
