package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	xrayRealityInboundTag = "reality-in"
	xrayUserAPITimeout    = 15 * time.Second
)

var (
	errXrayNeedsRestart = errors.New("xray change needs a restart")
	xrayAddedUsersRe    = regexp.MustCompile(`Added (\d+) user\(s\) in total`)
	xrayRemovedUsersRe  = regexp.MustCompile(`Removed (\d+) user\(s\) in total`)
)

// applyXrayConfig writes the rendered Xray config and makes the running Xray
// pick it up. Changes that only touch the REALITY client list are applied live
// through the Xray HandlerService so active sessions survive; anything else, or
// a failed live update, falls back to a container restart.
func applyXrayConfig(cfg envConfig, xrayRaw []byte, approvedDeviceCount int) error {
	oldRaw, _ := os.ReadFile(xrayConfigPath(cfg))
	xrayChanged := string(oldRaw) != string(xrayRaw)
	restartPending := xrayRestartPending(cfg)
	if !xrayChanged && !restartPending {
		return nil
	}
	if cfg.XrayContainer == "" {
		return errors.New("xray config changed but XRAY_CONTAINER_NAME is not configured")
	}
	if xrayChanged {
		if err := markXrayRestartPending(cfg); err != nil {
			return fmt.Errorf("mark xray restart pending: %w", err)
		}
		if err := writeXrayConfigBytes(cfg, xrayRaw); err != nil {
			return fmt.Errorf("write xray config: %w", err)
		}
	}
	if xrayChanged && !restartPending {
		err := hotApplyXrayUsers(cfg, oldRaw, xrayRaw)
		if err == nil {
			if err := clearXrayRestartPending(cfg); err != nil {
				return fmt.Errorf("clear xray restart pending: %w", err)
			}
			log.Printf("xray materialized approved_devices=%d without restart", approvedDeviceCount)
			return nil
		}
		if !errors.Is(err, errXrayNeedsRestart) {
			log.Printf("xray live user update failed, falling back to restart: %v", err)
		}
	}
	log.Printf("xray config changed; restarting container %s via %s", cfg.XrayContainer, cfg.DockerSocket)
	if err := restartDockerContainer(cfg.DockerSocket, cfg.XrayContainer); err != nil {
		return fmt.Errorf("restart xray container %s: %w", cfg.XrayContainer, err)
	}
	if err := clearXrayRestartPending(cfg); err != nil {
		return fmt.Errorf("clear xray restart pending: %w", err)
	}
	log.Printf("xray materialized approved_devices=%d and restarted %s", approvedDeviceCount, cfg.XrayContainer)
	return nil
}

type xrayUserDiff struct {
	Remove []string
	Add    []map[string]any
}

func hotApplyXrayUsers(cfg envConfig, oldRaw, newRaw []byte) error {
	diff, err := diffXrayUsers(oldRaw, newRaw)
	if err != nil {
		return err
	}
	if len(diff.Remove) > 0 {
		command := append([]string{
			"/usr/local/bin/xray", "api", "rmu",
			fmt.Sprintf("--server=127.0.0.1:%d", xrayAPIInPort),
			"-tag=" + xrayRealityInboundTag,
		}, diff.Remove...)
		out, err := execInXrayContainer(cfg, command, xrayUserAPITimeout)
		if err != nil {
			return fmt.Errorf("xray rmu: %w", err)
		}
		if err := expectXrayUserCount(xrayRemovedUsersRe, out, len(diff.Remove)); err != nil {
			return fmt.Errorf("xray rmu: %w", err)
		}
	}
	if len(diff.Add) > 0 {
		// The Xray container mounts the same worker-state directory at the same
		// path, so the request file is readable from inside it.
		path := filepath.Join(cfg.StateDir, "xray", "users-add.json")
		if err := writeJSONFile(path, xrayUserAddDocument(diff.Add), 0o600); err != nil {
			return err
		}
		defer os.Remove(path)
		command := []string{
			"/usr/local/bin/xray", "api", "adu",
			fmt.Sprintf("--server=127.0.0.1:%d", xrayAPIInPort),
			path,
		}
		out, err := execInXrayContainer(cfg, command, xrayUserAPITimeout)
		if err != nil {
			return fmt.Errorf("xray adu: %w", err)
		}
		if err := expectXrayUserCount(xrayAddedUsersRe, out, len(diff.Add)); err != nil {
			return fmt.Errorf("xray adu: %w", err)
		}
	}
	return nil
}

func expectXrayUserCount(re *regexp.Regexp, out []byte, want int) error {
	match := re.FindSubmatch(out)
	if match == nil {
		return fmt.Errorf("unexpected output: %s", strings.TrimSpace(string(out)))
	}
	got, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("applied %d of %d users: %s", got, want, strings.TrimSpace(string(out)))
	}
	return nil
}

func xrayUserAddDocument(clients []map[string]any) map[string]any {
	items := make([]any, 0, len(clients))
	for _, client := range clients {
		items = append(items, client)
	}
	return map[string]any{
		// Xray builds (but does not bind) this inbound to extract the users, and
		// its builder requires a port.
		"inbounds": []any{map[string]any{
			"tag":      xrayRealityInboundTag,
			"port":     xrayInPort,
			"protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    items,
			},
		}},
	}
}

// diffXrayUsers returns errXrayNeedsRestart unless the old config is known to
// have the HandlerService enabled and the two configs differ only in the
// REALITY inbound client list.
func diffXrayUsers(oldRaw, newRaw []byte) (xrayUserDiff, error) {
	if len(oldRaw) == 0 {
		return xrayUserDiff{}, errXrayNeedsRestart
	}
	oldDoc, oldClients, err := splitXrayClients(oldRaw)
	if err != nil {
		return xrayUserDiff{}, errXrayNeedsRestart
	}
	newDoc, newClients, err := splitXrayClients(newRaw)
	if err != nil {
		return xrayUserDiff{}, err
	}
	if !xrayHandlerServiceEnabled(oldDoc) || string(oldDoc) != string(newDoc) {
		return xrayUserDiff{}, errXrayNeedsRestart
	}
	var diff xrayUserDiff
	for email, oldClient := range oldClients {
		newClient, ok := newClients[email]
		if !ok || !sameJSON(oldClient, newClient) {
			diff.Remove = append(diff.Remove, email)
		}
	}
	for email, newClient := range newClients {
		oldClient, ok := oldClients[email]
		if !ok || !sameJSON(oldClient, newClient) {
			diff.Add = append(diff.Add, newClient)
		}
	}
	sort.Strings(diff.Remove)
	sort.Slice(diff.Add, func(i, j int) bool {
		return fmt.Sprint(diff.Add[i]["email"]) < fmt.Sprint(diff.Add[j]["email"])
	})
	return diff, nil
}

// splitXrayClients returns the config with the REALITY client list blanked out,
// in canonical JSON form, plus the clients keyed by email.
func splitXrayClients(raw []byte) ([]byte, map[string]map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	inbounds, _ := doc["inbounds"].([]any)
	var clients []any
	found := false
	for _, item := range inbounds {
		inbound, _ := item.(map[string]any)
		if inbound == nil || inbound["tag"] != xrayRealityInboundTag {
			continue
		}
		settings, _ := inbound["settings"].(map[string]any)
		if settings == nil {
			return nil, nil, errors.New("reality inbound has no settings")
		}
		clients, _ = settings["clients"].([]any)
		settings["clients"] = nil
		found = true
	}
	if !found {
		return nil, nil, errors.New("reality inbound not found")
	}
	byEmail := make(map[string]map[string]any, len(clients))
	for _, item := range clients {
		client, _ := item.(map[string]any)
		email, _ := client["email"].(string)
		if client == nil || email == "" {
			return nil, nil, errors.New("xray client without email")
		}
		if _, dup := byEmail[email]; dup {
			return nil, nil, fmt.Errorf("duplicate xray client email %q", email)
		}
		byEmail[email] = client
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}
	return canonical, byEmail, nil
}

func xrayHandlerServiceEnabled(canonical []byte) bool {
	var doc struct {
		API struct {
			Services []string `json:"services"`
		} `json:"api"`
	}
	if err := json.Unmarshal(canonical, &doc); err != nil {
		return false
	}
	for _, service := range doc.API.Services {
		if service == "HandlerService" {
			return true
		}
	}
	return false
}

func sameJSON(a, b any) bool {
	left, err1 := json.Marshal(a)
	right, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(left) == string(right)
}
