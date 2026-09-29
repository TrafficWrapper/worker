package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// fakeCommands replaces runCommand for the test and records every command.
// fail decides which commands fail; nil means none do.
func fakeCommands(t *testing.T, fail func(cmd string) bool) *[]string {
	t.Helper()
	var ran []string
	orig := runCommand
	runCommand = func(name string, args ...string) ([]byte, error) {
		cmd := strings.Join(append([]string{name}, args...), " ")
		ran = append(ran, cmd)
		if fail != nil && fail(cmd) {
			return []byte("fake failure"), errors.New("exit status 1")
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommand = orig })
	return &ran
}

func writeTestConfig(t *testing.T, cfg Config) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "awg-gw.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// stubUAPIProbe makes the healthcheck's UAPI probe succeed and records the
// socket paths it was asked about.
func stubUAPIProbe(t *testing.T) *[]string {
	t.Helper()
	var probed []string
	old := probeUAPI
	probeUAPI = func(path string) error { probed = append(probed, path); return nil }
	t.Cleanup(func() { probeUAPI = old })
	return &probed
}

func TestHealthcheckChecksInterfaceOfGivenConfig(t *testing.T) {
	cfg := validTestConfig()
	cfg.Interface = "awg2"
	path := writeTestConfig(t, cfg)
	probed := stubUAPIProbe(t)
	defer func() {
		if want := filepath.Join(uapiSocketDirectory, "awg2.sock"); len(*probed) != 1 || (*probed)[0] != want {
			t.Errorf("healthcheck probed %v, want %s", *probed, want)
		}
	}()

	ran := fakeCommands(t, nil)
	if err := runHealthcheck([]string{"--config", path}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*ran, "\n"); got != "ip link show dev awg2" {
		t.Fatalf("healthcheck ran %q, want the profile interface awg2", got)
	}

	fakeCommands(t, func(string) bool { return true })
	if err := runHealthcheck([]string{"--config", path}); err == nil {
		t.Fatal("missing interface reported healthy")
	}
}

// fakeTUN replaces createTUN and records the commands already run when the
// TUN would be created. It fails, so runGateway stops right after.
func fakeTUN(t *testing.T, ran *[]string) *[]string {
	t.Helper()
	var before []string
	orig := createTUN
	createTUN = func(string, int) (tun.Device, error) {
		before = append([]string(nil), *ran...)
		return nil, errors.New("fake TUN stop")
	}
	t.Cleanup(func() { createTUN = orig })
	return &before
}

func TestGatewayInstallsIsolationBeforeCreatingTUN(t *testing.T) {
	t.Setenv("WORKER_ALLOW_PRIVATE_EGRESS", "")
	t.Setenv("WORKER_BLOCK_SMTP", "")
	t.Setenv("AWG_LOG_LEVEL", "silent")
	path := writeTestConfig(t, validTestConfig())

	ran := fakeCommands(t, nil)
	before := fakeTUN(t, ran)
	err := runGateway(path)
	if err == nil || !strings.Contains(err.Error(), "fake TUN stop") {
		t.Fatalf("runGateway error=%v, want the fake TUN failure", err)
	}
	isolation := strings.Join(*before, "\n")
	for _, want := range []string{"trafficwrapper_awg_isolation forward iifname awg1 ip daddr", "tcp dport { 25, 465, 587 } drop"} {
		if !strings.Contains(isolation, want) {
			t.Fatalf("isolation rule %q not installed before the TUN:\n%s", want, isolation)
		}
	}
}

func TestGatewayDoesNotStartWithoutIsolation(t *testing.T) {
	t.Setenv("WORKER_ALLOW_PRIVATE_EGRESS", "")
	t.Setenv("WORKER_BLOCK_SMTP", "")
	t.Setenv("AWG_LOG_LEVEL", "silent")
	path := writeTestConfig(t, validTestConfig())

	ran := fakeCommands(t, func(cmd string) bool { return strings.Contains(cmd, "_isolation") })
	tunCalled := false
	orig := createTUN
	createTUN = func(string, int) (tun.Device, error) {
		tunCalled = true
		return nil, errors.New("fake TUN stop")
	}
	t.Cleanup(func() { createTUN = orig })

	err := runGateway(path)
	if err == nil || strings.Contains(err.Error(), "fake TUN stop") {
		t.Fatalf("runGateway error=%v, want the isolation failure", err)
	}
	if tunCalled {
		t.Fatalf("TUN created although isolation failed; commands: %v", *ran)
	}
}

func TestGatewayBlocksWorkerAddressesFromTunnel(t *testing.T) {
	t.Setenv("WORKER_ALLOW_PRIVATE_EGRESS", "")
	t.Setenv("WORKER_BLOCK_SMTP", "")
	t.Setenv("AWG_LOG_LEVEL", "silent")
	cfg := validTestConfig()
	cfg.WorkerAddresses = []string{"203.0.113.10", "198.51.100.7", "2001:db8::1"}
	path := writeTestConfig(t, cfg)

	ran := fakeCommands(t, nil)
	before := fakeTUN(t, ran)
	if err := runGateway(path); err == nil || !strings.Contains(err.Error(), "fake TUN stop") {
		t.Fatalf("runGateway error=%v, want the fake TUN failure", err)
	}
	rules := strings.Join(*before, "\n")
	for _, want := range []string{
		"forward iifname awg1 ip daddr { 203.0.113.10, 198.51.100.7 } drop",
		"forward iifname awg1 ip6 daddr { 2001:db8::1 } drop",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("worker address rule %q missing:\n%s", want, rules)
		}
	}

	// The private egress opt-out lifts this block like the private ranges.
	t.Setenv("WORKER_ALLOW_PRIVATE_EGRESS", "1")
	ran = fakeCommands(t, nil)
	before = fakeTUN(t, ran)
	_ = runGateway(path)
	if rules := strings.Join(*before, "\n"); strings.Contains(rules, "203.0.113.10") || !strings.Contains(rules, "dport") {
		t.Fatalf("private egress opt-out must keep only the SMTP rule:\n%s", rules)
	}
}

func TestValidateConfigRejectsNonIPWorkerAddresses(t *testing.T) {
	for _, value := range []string{"worker.example.net", "203.0.113.10/32", "fe80::1%eth0", ""} {
		cfg := validTestConfig()
		cfg.WorkerAddresses = []string{value}
		if err := validateConfig(cfg); err == nil {
			t.Fatalf("worker address %q accepted", value)
		}
	}
	cfg := validTestConfig()
	cfg.WorkerAddresses = []string{"203.0.113.10", "2001:db8::1"}
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestHealthcheckRequiresExplicitConfig(t *testing.T) {
	ran := fakeCommands(t, nil)
	missing := filepath.Join(t.TempDir(), "missing.json")
	if err := runHealthcheck([]string{"--config", missing}); err == nil {
		t.Fatal("missing explicit config reported healthy")
	}
	if len(*ran) != 0 {
		t.Fatalf("commands ran without a config: %v", *ran)
	}
}

type scriptedListener struct {
	steps []func() (net.Conn, error)
	i     int
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	step := l.steps[l.i]
	l.i++
	return step()
}
func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return nil }

type countingHandler struct{ handled chan net.Conn }

func (h countingHandler) IpcHandle(c net.Conn) { h.handled <- c }

// deadAfterErrorListener behaves like amneziawg-go's UAPIListener: after
// the first error its accept goroutine is gone and Accept blocks until Close.
type deadAfterErrorListener struct {
	err    error
	once   sync.Once
	failed bool
	closed chan struct{}
}

func newDeadAfterErrorListener(err error) *deadAfterErrorListener {
	return &deadAfterErrorListener{err: err, closed: make(chan struct{})}
}

func (l *deadAfterErrorListener) Accept() (net.Conn, error) {
	if !l.failed {
		l.failed = true
		return nil, l.err
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *deadAfterErrorListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}
func (l *deadAfterErrorListener) Addr() net.Addr { return nil }

func fastUAPIReopen(t *testing.T) {
	t.Helper()
	oldMin, oldMax, oldN := uapiReopenMinDelay, uapiReopenMaxDelay, uapiReopenAttempts
	uapiReopenMinDelay, uapiReopenMaxDelay, uapiReopenAttempts = time.Millisecond, 2*time.Millisecond, 3
	t.Cleanup(func() { uapiReopenMinDelay, uapiReopenMaxDelay, uapiReopenAttempts = oldMin, oldMax, oldN })
}

func TestServeUAPIReopensListenerAfterAcceptError(t *testing.T) {
	fastUAPIReopen(t)
	for _, cause := range []error{syscall.EMFILE, os.ErrNotExist} {
		first := newDeadAfterErrorListener(cause)
		client, server := net.Pipe()
		defer client.Close()
		second := &scriptedListener{steps: []func() (net.Conn, error){
			func() (net.Conn, error) { return server, nil },
			func() (net.Conn, error) { select {} },
		}}
		reopened := 0
		reopen := func() (net.Listener, error) {
			reopened++
			if reopened == 1 {
				return nil, syscall.EMFILE // one failed attempt is retried
			}
			return second, nil
		}
		h := countingHandler{handled: make(chan net.Conn, 1)}
		errs := make(chan error, 1)
		go serveUAPI(t.Context(), h, first, reopen, errs)
		select {
		case c := <-h.handled:
			if c != server {
				t.Fatal("wrong connection handled")
			}
		case err := <-errs:
			t.Fatalf("%v: serveUAPI gave up: %v", cause, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("%v: no connection handled after the listener failed; UAPI is silently dead", cause)
		}
		select {
		case <-first.closed:
		default:
			t.Fatalf("%v: failed listener not closed", cause)
		}
	}
}

func TestServeUAPIExitsWhenSocketCannotBeReopened(t *testing.T) {
	fastUAPIReopen(t)
	reopen := func() (net.Listener, error) { return nil, syscall.EMFILE }
	errs := make(chan error, 1)
	go serveUAPI(t.Context(), countingHandler{}, newDeadAfterErrorListener(syscall.EMFILE), reopen, errs)
	select {
	case err := <-errs:
		if !errors.Is(err, syscall.EMFILE) {
			t.Fatalf("unexpected error %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway kept running without a UAPI socket")
	}
}

func TestServeUAPIStopsQuietlyOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	l := newDeadAfterErrorListener(nil)
	l.failed = true // Accept blocks until Close
	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		serveUAPI(ctx, countingHandler{}, l, func() (net.Listener, error) { return nil, errors.New("reopen on shutdown") }, errs)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveUAPI did not stop on shutdown")
	}
	select {
	case err := <-errs:
		t.Fatalf("shutdown reported as failure: %v", err)
	default:
	}
}

// fakeUAPIServer answers "get=1" on a unix socket like a gateway would.
func fakeUAPIServer(t *testing.T, answer string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "uapi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "awg2.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 64)
			_, _ = c.Read(buf)
			_, _ = io.WriteString(c, answer)
			c.Close()
		}
	}()
	return dir
}

func TestHealthcheckProbesUAPI(t *testing.T) {
	cfg := validTestConfig()
	cfg.Interface = "awg2"
	path := writeTestConfig(t, cfg)
	fakeCommands(t, nil)
	old := uapiSocketDirectory
	t.Cleanup(func() { uapiSocketDirectory = old })

	uapiSocketDirectory = fakeUAPIServer(t, "private_key=00\nerrno=0\n\n")
	if err := runHealthcheck([]string{"--config", path}); err != nil {
		t.Fatalf("answering UAPI reported unhealthy: %v", err)
	}
	uapiSocketDirectory = fakeUAPIServer(t, "errno=1\n\n")
	if err := runHealthcheck([]string{"--config", path}); err == nil {
		t.Fatal("UAPI error reported healthy")
	}
	uapiSocketDirectory = t.TempDir() // no socket
	if err := runHealthcheck([]string{"--config", path}); err == nil {
		t.Fatal("missing UAPI socket reported healthy")
	}
}

// TestUAPIListenerRecoversFromDeletedSocket runs the real amneziawg-go
// listener. It needs the default socket directory to be writable (root).
func TestUAPIListenerRecoversFromDeletedSocket(t *testing.T) {
	if err := os.MkdirAll("/var/run/amneziawg", 0o755); err != nil {
		t.Skipf("socket directory not writable: %v", err)
	}
	fastUAPIReopen(t)
	iface := fmt.Sprintf("twt%d", os.Getpid()%100000)
	sock := filepath.Join("/var/run/amneziawg", iface+".sock")
	l, err := openUAPI(iface)
	if err != nil {
		t.Skipf("uapi listen: %v", err)
	}
	h := countingHandler{handled: make(chan net.Conn, 4)}
	errs := make(chan error, 1)
	go serveUAPI(t.Context(), h, l, func() (net.Listener, error) { return openUAPI(iface) }, errs)
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := net.Dial("unix", sock); err == nil {
			defer c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("UAPI socket not recreated after deletion")
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case c := <-h.handled:
		c.Close()
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("connection on the recreated socket not handled")
	}
}
