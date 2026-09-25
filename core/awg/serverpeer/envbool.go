package serverpeer

import (
	"fmt"
	"os"
	"strings"
)

// ParseBool reads a boolean switch shared by the agent and awg-gw, so both
// services agree on every value. Empty means fallback; an unknown value is an
// error instead of silently turning a protection on or off.
func ParseBool(key, value string, fallback bool) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return fallback, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be one of 1/0, true/false, yes/no, on/off, got %q", key, value)
	}
}

// EnvBool is ParseBool for the environment variable key.
func EnvBool(key string, fallback bool) (bool, error) {
	return ParseBool(key, os.Getenv(key), fallback)
}
