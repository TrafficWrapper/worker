package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

const rateLimitInterval = 30 * time.Second

// Shaping IDs are HTB class minors and filter priorities, both 16-bit.
const (
	firstShapingID = 16
	lastShapingID  = 0xffff
)

// rateLimit is a per-client AWG bandwidth cap in Mbit/s; 0 means unlimited.
type rateLimit struct {
	IP           string
	DownloadMbps int
	UploadMbps   int
}

// shapedClient is the applied shaping of one client. ID is its HTB class
// minor and the priority of both its filters, so one client's rules can be
// changed or removed without touching the others.
type shapedClient struct {
	ID           int
	DownloadMbps int
	UploadMbps   int
}

// loadRateLimits reads the limits the agent wrote into the peer registry.
func loadRateLimits(path string, now time.Time) ([]rateLimit, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var registry registryFile
	if err := json.Unmarshal(raw, &registry); err != nil {
		return nil, err
	}
	var limits []rateLimit
	for _, client := range registry.Clients {
		if client.DownloadMbps <= 0 && client.UploadMbps <= 0 {
			continue
		}
		if !client.ExpiresAt.IsZero() && !client.ExpiresAt.After(now) {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(client.InternalIP))
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
			continue
		}
		limits = append(limits, rateLimit{IP: prefix.Addr().String(), DownloadMbps: client.DownloadMbps, UploadMbps: client.UploadMbps})
	}
	sort.Slice(limits, func(i, j int) bool { return limits[i].IP < limits[j].IP })
	return limits, nil
}

// rateLimitCommands rebuilds the shaping from scratch: an HTB class per
// limited client for traffic towards it (download) and an ingress policer for
// traffic from it (upload). Unclassified traffic is not shaped.
func rateLimitCommands(iface string, limits []rateLimit) [][]string {
	commands, _ := rateLimitRebuild(iface, limits)
	return commands
}

// rateLimitRebuild is rateLimitCommands plus the shaping it leaves in place.
// The first two commands delete qdiscs that may not exist yet.
func rateLimitRebuild(iface string, limits []rateLimit) ([][]string, map[string]shapedClient) {
	commands := [][]string{
		{"tc", "qdisc", "del", "dev", iface, "root"},
		{"tc", "qdisc", "del", "dev", iface, "ingress"},
	}
	shaped := map[string]shapedClient{}
	if len(limits) == 0 {
		return commands, shaped
	}
	commands = append(commands,
		[]string{"tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb"},
		[]string{"tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"},
	)
	for i, limit := range limits {
		id := i + firstShapingID
		if id > lastShapingID {
			fmt.Fprintf(os.Stderr, "warning: rate limit for %s skipped: no free shaping ID\n", limit.IP)
			continue
		}
		client := shapedClient{ID: id, DownloadMbps: limit.DownloadMbps, UploadMbps: limit.UploadMbps}
		commands = append(commands, downloadAddCommands(iface, limit.IP, client)...)
		commands = append(commands, uploadAddCommands(iface, limit.IP, client)...)
		shaped[limit.IP] = client
	}
	return commands, shaped
}

// rateLimitDiff changes only the clients whose limits differ from applied:
// new clients get a free ID, removed ones lose their class and filters, and
// changed rates replace only that client's class rate or policer.
func rateLimitDiff(iface string, applied map[string]shapedClient, limits []rateLimit) ([][]string, map[string]shapedClient) {
	wanted := make(map[string]bool, len(limits))
	for _, limit := range limits {
		wanted[limit.IP] = true
	}
	var commands [][]string
	used := map[int]bool{}
	for _, ip := range sortedKeys(applied) {
		client := applied[ip]
		if wanted[ip] {
			used[client.ID] = true
			continue
		}
		commands = append(commands, downloadDelCommands(iface, client)...)
		commands = append(commands, uploadDelCommands(iface, client)...)
	}
	shaped := make(map[string]shapedClient, len(limits))
	nextID := firstShapingID
	for _, limit := range limits {
		old, ok := applied[limit.IP]
		client := shapedClient{ID: old.ID, DownloadMbps: limit.DownloadMbps, UploadMbps: limit.UploadMbps}
		if !ok {
			for nextID <= lastShapingID && used[nextID] {
				nextID++
			}
			if nextID > lastShapingID {
				fmt.Fprintf(os.Stderr, "warning: rate limit for %s skipped: no free shaping ID\n", limit.IP)
				continue
			}
			client.ID = nextID
			used[nextID] = true
			commands = append(commands, downloadAddCommands(iface, limit.IP, client)...)
			commands = append(commands, uploadAddCommands(iface, limit.IP, client)...)
			shaped[limit.IP] = client
			continue
		}
		switch {
		case old.DownloadMbps == client.DownloadMbps:
		case old.DownloadMbps > 0 && client.DownloadMbps > 0:
			rate := fmt.Sprintf("%dmbit", client.DownloadMbps)
			commands = append(commands, []string{"tc", "class", "change", "dev", iface, "parent", "1:", "classid", classID(client), "htb", "rate", rate, "ceil", rate})
		case old.DownloadMbps > 0:
			commands = append(commands, downloadDelCommands(iface, old)...)
		default:
			commands = append(commands, downloadAddCommands(iface, limit.IP, client)...)
		}
		if old.UploadMbps != client.UploadMbps {
			// A policer cannot be changed in place; its filter is replaced.
			commands = append(commands, uploadDelCommands(iface, old)...)
			commands = append(commands, uploadAddCommands(iface, limit.IP, client)...)
		}
		shaped[limit.IP] = client
	}
	return commands, shaped
}

func classID(client shapedClient) string {
	return fmt.Sprintf("1:%x", client.ID)
}

func downloadAddCommands(iface, ip string, client shapedClient) [][]string {
	if client.DownloadMbps <= 0 {
		return nil
	}
	rate := fmt.Sprintf("%dmbit", client.DownloadMbps)
	return [][]string{
		{"tc", "class", "add", "dev", iface, "parent", "1:", "classid", classID(client), "htb", "rate", rate, "ceil", rate},
		{"tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", fmt.Sprint(client.ID), "u32", "match", "ip", "dst", ip + "/32", "flowid", classID(client)},
	}
}

func downloadDelCommands(iface string, client shapedClient) [][]string {
	if client.DownloadMbps <= 0 {
		return nil
	}
	// The filter goes first: a class that a filter points to cannot be deleted.
	return [][]string{
		{"tc", "filter", "del", "dev", iface, "parent", "1:", "protocol", "ip", "prio", fmt.Sprint(client.ID)},
		{"tc", "class", "del", "dev", iface, "classid", classID(client)},
	}
}

func uploadAddCommands(iface, ip string, client shapedClient) [][]string {
	if client.UploadMbps <= 0 {
		return nil
	}
	return [][]string{{
		"tc", "filter", "add", "dev", iface, "parent", "ffff:", "protocol", "ip", "prio", fmt.Sprint(client.ID), "u32", "match", "ip", "src", ip + "/32",
		"police", "rate", fmt.Sprintf("%dmbit", client.UploadMbps), "burst", policerBurst(client.UploadMbps), "drop", "flowid", ":1",
	}}
}

func uploadDelCommands(iface string, client shapedClient) [][]string {
	if client.UploadMbps <= 0 {
		return nil
	}
	return [][]string{{"tc", "filter", "del", "dev", iface, "parent", "ffff:", "protocol", "ip", "prio", fmt.Sprint(client.ID)}}
}

func sortedKeys(m map[string]shapedClient) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// policerBurst allows about 10ms of traffic at the limit, at least 32 KiB.
func policerBurst(mbps int) string {
	burst := mbps * 1_000_000 / 8 / 100
	if burst < 32*1024 {
		burst = 32 * 1024
	}
	return fmt.Sprintf("%db", burst)
}

// rateShaper keeps the applied shaping of one interface, so a change of some
// limits only touches those clients instead of rebuilding everyone's.
type rateShaper struct {
	iface string
	// applied is nil until shaping is known to match it: at start and after
	// a failed apply, the next update rebuilds from scratch.
	applied map[string]shapedClient
}

// update applies limits and reports whether any tc command ran.
func (s *rateShaper) update(limits []rateLimit) (bool, error) {
	if s.applied != nil && sameShaping(s.applied, limits) {
		return false, nil
	}
	var commands [][]string
	var shaped map[string]shapedClient
	tolerated := 0
	if len(s.applied) == 0 || len(limits) == 0 {
		// Nothing is shaped yet or nothing will be: the qdiscs themselves
		// are added or removed.
		commands, shaped = rateLimitRebuild(s.iface, limits)
		tolerated = 2
	} else {
		commands, shaped = rateLimitDiff(s.iface, s.applied, limits)
	}
	for i, args := range commands {
		out, err := runCommand(args[0], args[1:]...)
		// Deleting a qdisc that does not exist yet is expected.
		if err != nil && i >= tolerated {
			s.applied = nil
			return false, fmt.Errorf("%s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	s.applied = shaped
	return true, nil
}

func sameShaping(applied map[string]shapedClient, limits []rateLimit) bool {
	if len(applied) != len(limits) {
		return false
	}
	for _, limit := range limits {
		client, ok := applied[limit.IP]
		if !ok || client.DownloadMbps != limit.DownloadMbps || client.UploadMbps != limit.UploadMbps {
			return false
		}
	}
	return true
}

// runRateLimits re-applies the limits whenever the registry changes them.
func runRateLimits(ctx context.Context, iface, registry string) {
	shaper := &rateShaper{iface: iface}
	ticker := time.NewTicker(rateLimitInterval)
	defer ticker.Stop()
	for {
		limits, err := loadRateLimits(registry, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: rate limits not loaded: %v\n", err)
		} else if changed, err := shaper.update(limits); err != nil {
			fmt.Fprintf(os.Stderr, "warning: rate limits not applied: %v\n", err)
		} else if changed {
			fmt.Printf("rate_limits=%d\n", len(limits))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
