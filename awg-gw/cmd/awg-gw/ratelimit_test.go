package main

import (
	"strings"
	"testing"
)

func updateShaper(t *testing.T, shaper *rateShaper, limits ...rateLimit) []string {
	t.Helper()
	ran := fakeCommands(t, nil)
	if _, err := shaper.update(limits); err != nil {
		t.Fatal(err)
	}
	return *ran
}

func TestRateShaperChangesOnlyClientsWhoseLimitsChanged(t *testing.T) {
	shaper := &rateShaper{iface: "awg1"}
	a := rateLimit{IP: "10.13.13.10", DownloadMbps: 20, UploadMbps: 5}
	b := rateLimit{IP: "10.13.13.11", DownloadMbps: 10}
	c := rateLimit{IP: "10.13.13.12", UploadMbps: 3}
	initial := strings.Join(updateShaper(t, shaper, a, b, c), "\n")
	for _, want := range []string{"tc qdisc del dev awg1 root", "classid 1:10", "classid 1:11", "match ip src 10.13.13.12/32"} {
		if !strings.Contains(initial, want) {
			t.Fatalf("initial shaping missing %q:\n%s", want, initial)
		}
	}

	if ran := updateShaper(t, shaper, a, b, c); len(ran) != 0 {
		t.Fatalf("unchanged limits ran tc: %v", ran)
	}

	b.DownloadMbps = 15
	got := updateShaper(t, shaper, a, b, c)
	want := []string{"tc class change dev awg1 parent 1: classid 1:11 htb rate 15mbit ceil 15mbit"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("download change ran:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	a.UploadMbps = 8
	got = updateShaper(t, shaper, a, b, c)
	want = []string{
		"tc filter del dev awg1 parent ffff: protocol ip prio 16",
		"tc filter add dev awg1 parent ffff: protocol ip prio 16 u32 match ip src 10.13.13.10/32 police rate 8mbit burst 32768b drop flowid :1",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("upload change ran:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Removing c frees its ID for the new client d.
	d := rateLimit{IP: "10.13.13.13", DownloadMbps: 7}
	got = updateShaper(t, shaper, a, b, d)
	want = []string{
		"tc filter del dev awg1 parent ffff: protocol ip prio 18",
		"tc class add dev awg1 parent 1: classid 1:12 htb rate 7mbit ceil 7mbit",
		"tc filter add dev awg1 parent 1: protocol ip prio 18 u32 match ip dst 10.13.13.13/32 flowid 1:12",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("add/remove ran:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	a.DownloadMbps = 0
	got = updateShaper(t, shaper, a, b, d)
	want = []string{
		"tc filter del dev awg1 parent 1: protocol ip prio 16",
		"tc class del dev awg1 classid 1:10",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("download removal ran:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	if cleared := updateShaper(t, shaper); len(cleared) != 2 {
		t.Fatalf("no limits must only clear shaping: %v", cleared)
	}
}

func TestRateShaperRebuildsAfterFailedApply(t *testing.T) {
	shaper := &rateShaper{iface: "awg1"}
	a := rateLimit{IP: "10.13.13.10", DownloadMbps: 20}
	b := rateLimit{IP: "10.13.13.11", DownloadMbps: 10}
	updateShaper(t, shaper, a, b)

	b.DownloadMbps = 15
	fakeCommands(t, func(string) bool { return true })
	if _, err := shaper.update([]rateLimit{a, b}); err == nil {
		t.Fatal("failed tc command not reported")
	}
	// The shaping state is unknown now, so everything is rebuilt.
	ran := strings.Join(updateShaper(t, shaper, a, b), "\n")
	if !strings.Contains(ran, "tc qdisc del dev awg1 root") || !strings.Contains(ran, "classid 1:11 htb rate 15mbit") {
		t.Fatalf("apply after a failure did not rebuild:\n%s", ran)
	}
}
