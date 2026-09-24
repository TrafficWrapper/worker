package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const rateLimitInterval = 30 * time.Second

// rateLimit is a per-client AWG bandwidth cap in Mbit/s; 0 means unlimited.
type rateLimit struct {
	IP           string
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
	commands := [][]string{
		{"tc", "qdisc", "del", "dev", iface, "root"},
		{"tc", "qdisc", "del", "dev", iface, "ingress"},
	}
	if len(limits) == 0 {
		return commands
	}
	commands = append(commands,
		[]string{"tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb"},
		[]string{"tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"},
	)
	for i, limit := range limits {
		host := limit.IP + "/32"
		if limit.DownloadMbps > 0 {
			classID := fmt.Sprintf("1:%x", i+16)
			rate := fmt.Sprintf("%dmbit", limit.DownloadMbps)
			commands = append(commands,
				[]string{"tc", "class", "add", "dev", iface, "parent", "1:", "classid", classID, "htb", "rate", rate, "ceil", rate},
				[]string{"tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "dst", host, "flowid", classID},
			)
		}
		if limit.UploadMbps > 0 {
			commands = append(commands, []string{
				"tc", "filter", "add", "dev", iface, "parent", "ffff:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "src", host,
				"police", "rate", fmt.Sprintf("%dmbit", limit.UploadMbps), "burst", policerBurst(limit.UploadMbps), "drop", "flowid", ":1",
			})
		}
	}
	return commands
}

// policerBurst allows about 10ms of traffic at the limit, at least 32 KiB.
func policerBurst(mbps int) string {
	burst := mbps * 1_000_000 / 8 / 100
	if burst < 32*1024 {
		burst = 32 * 1024
	}
	return fmt.Sprintf("%db", burst)
}

func applyRateLimits(iface string, limits []rateLimit) error {
	for i, args := range rateLimitCommands(iface, limits) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		// Deleting a qdisc that does not exist yet is expected.
		if err != nil && i >= 2 {
			return fmt.Errorf("%s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// runRateLimits re-applies the limits whenever the registry changes them.
func runRateLimits(ctx context.Context, iface, registry string) {
	var applied string
	ticker := time.NewTicker(rateLimitInterval)
	defer ticker.Stop()
	for {
		limits, err := loadRateLimits(registry, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: rate limits not loaded: %v\n", err)
		} else if key := fmt.Sprint(limits); key != applied {
			if err := applyRateLimits(iface, limits); err != nil {
				fmt.Fprintf(os.Stderr, "warning: rate limits not applied: %v\n", err)
			} else {
				applied = key
				fmt.Printf("rate_limits=%d\n", len(limits))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
