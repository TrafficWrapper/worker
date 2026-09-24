package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	netstacktun "github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

func TestSOCKSAcceptTemporaryErrorDoesNotStopLoop(t *testing.T) {
	oldMin, oldMax := socksAcceptBackoffMin, socksAcceptBackoffMax
	socksAcceptBackoffMin = time.Millisecond
	socksAcceptBackoffMax = time.Millisecond
	defer func() {
		socksAcceptBackoffMin = oldMin
		socksAcceptBackoffMax = oldMax
	}()

	listener := &scriptedListener{
		errs: []error{
			temporaryNetError{err: errors.New("too many open files")},
			net.ErrClosed,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &socksServer{listener: listener, ctx: ctx, cancel: cancel}
	server.wg.Add(1)
	server.serve(ctx)

	if got := listener.calls.Load(); got != 2 {
		t.Fatalf("Accept calls=%d, want 2", got)
	}
}

func TestSOCKSProxyIdleTimeoutClosesIdleSession(t *testing.T) {
	oldIdle := socksProxyIdleTimeout
	socksProxyIdleTimeout = 25 * time.Millisecond
	defer func() { socksProxyIdleTimeout = oldIdle }()

	leftProxy, leftClient := net.Pipe()
	rightProxy, rightClient := net.Pipe()
	defer leftClient.Close()
	defer rightClient.Close()

	done := make(chan error, 1)
	go func() { done <- proxy(context.Background(), leftProxy, rightProxy) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not close idle session")
	}

	if _, err := leftClient.Write([]byte("x")); err == nil {
		t.Fatal("left client write succeeded after idle close")
	}
	if _, err := rightClient.Write([]byte("x")); err == nil {
		t.Fatal("right client write succeeded after idle close")
	}
}

func TestSOCKSProxyHalfCloseAllowsResponseAfterClientFIN(t *testing.T) {
	oldIdle := socksProxyIdleTimeout
	socksProxyIdleTimeout = 2 * time.Second
	defer func() { socksProxyIdleTimeout = oldIdle }()

	leftClient, leftProxy := tcpPair(t)
	rightClient, rightProxy := tcpPair(t)
	defer leftClient.Close()
	defer rightClient.Close()

	proxyDone := make(chan error, 1)
	go func() { proxyDone <- proxy(context.Background(), leftProxy, rightProxy) }()

	rightDone := make(chan []byte, 1)
	go func() {
		_ = rightClient.SetReadDeadline(time.Now().Add(time.Second))
		request, err := io.ReadAll(rightClient)
		if err != nil {
			t.Errorf("right read: %v", err)
			rightDone <- nil
			return
		}
		_ = rightClient.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := rightClient.Write([]byte("response-after-fin")); err != nil {
			t.Errorf("right write response: %v", err)
			rightDone <- nil
			return
		}
		if err := rightClient.CloseWrite(); err != nil {
			t.Errorf("right close write: %v", err)
		}
		rightDone <- request
	}()

	if _, err := leftClient.Write([]byte("request")); err != nil {
		t.Fatalf("left write request: %v", err)
	}
	if err := leftClient.CloseWrite(); err != nil {
		t.Fatalf("left close write: %v", err)
	}
	_ = leftClient.SetReadDeadline(time.Now().Add(time.Second))
	response, err := io.ReadAll(leftClient)
	if err != nil {
		t.Fatalf("left read response: %v", err)
	}

	select {
	case request := <-rightDone:
		if string(request) != "request" {
			t.Fatalf("right request=%q, want request", string(request))
		}
	case <-time.After(time.Second):
		t.Fatal("right side did not finish")
	}
	if string(response) != "response-after-fin" {
		t.Fatalf("left response=%q, want response-after-fin", string(response))
	}
	select {
	case err := <-proxyDone:
		if err != nil {
			t.Fatalf("proxy error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not finish")
	}
}

func TestResolveTargetIPDoesNotUseResolver(t *testing.T) {
	oldLookup := lookupSOCKSTargetHost
	lookupSOCKSTargetHost = func(context.Context, *netstacktun.Net, string) ([]string, error) {
		t.Fatal("IP target unexpectedly used DNS resolver")
		return nil, nil
	}
	defer func() { lookupSOCKSTargetHost = oldLookup }()

	addr, err := resolveTarget(context.Background(), nil, socksTarget{host: "203.0.113.8", port: 443})
	if err != nil {
		t.Fatalf("resolve IP target: %v", err)
	}
	if got := addr.String(); got != "203.0.113.8:443" {
		t.Fatalf("resolved target=%s, want 203.0.113.8:443", got)
	}
}

func TestResolveTargetDomainUsesTunnelResolver(t *testing.T) {
	oldLookup := lookupSOCKSTargetHost
	var called atomic.Bool
	lookupSOCKSTargetHost = func(ctx context.Context, tnet *netstacktun.Net, host string) ([]string, error) {
		called.Store(true)
		if host != "example.com" {
			t.Fatalf("resolver host=%q, want example.com", host)
		}
		if tnet != nil {
			t.Fatal("test passed unexpected netstack instance")
		}
		return []string{"2001:db8::1", "198.51.100.17"}, nil
	}
	defer func() { lookupSOCKSTargetHost = oldLookup }()

	addr, err := resolveTarget(context.Background(), nil, socksTarget{host: "example.com", port: 8443})
	if err != nil {
		t.Fatalf("resolve domain target: %v", err)
	}
	if !called.Load() {
		t.Fatal("domain target did not use tunnel resolver")
	}
	if got := addr.String(); got != "198.51.100.17:8443" {
		t.Fatalf("resolved target=%s, want 198.51.100.17:8443", got)
	}
}

func TestResolveTargetDomainRequiresTunnelResolver(t *testing.T) {
	oldLookup := lookupSOCKSTargetHost
	defer func() { lookupSOCKSTargetHost = oldLookup }()

	_, err := resolveTarget(context.Background(), nil, socksTarget{host: "example.com", port: 443})
	if err == nil {
		t.Fatal("resolve domain target succeeded without tunnel resolver")
	}
}

func TestSOCKSCloseCancelsActiveSession(t *testing.T) {
	oldLookup := lookupSOCKSTargetHost
	lookupSOCKSTargetHost = func(context.Context, *netstacktun.Net, string) ([]string, error) {
		return []string{"198.51.100.17"}, nil
	}
	defer func() { lookupSOCKSTargetHost = oldLookup }()

	upstreamServer, upstreamClient := net.Pipe()
	defer upstreamClient.Close()
	dialed := make(chan struct{})
	oldDial := dialSOCKSTargetTCP
	dialSOCKSTargetTCP = func(context.Context, *netstacktun.Net, netip.AddrPort) (net.Conn, error) {
		close(dialed)
		return upstreamServer, nil
	}
	defer func() { dialSOCKSTargetTCP = oldDial }()

	ctx, cancel := context.WithCancel(context.Background())
	server := &socksServer{ctx: ctx, cancel: cancel}
	client, serverConn := net.Pipe()
	done := make(chan error, 1)
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		done <- server.handle(ctx, serverConn)
	}()
	defer client.Close()

	if _, err := client.Write([]byte{socksVersion5, 0x01, socksNoAuth}); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read handshake reply: %v", err)
	}
	if _, err := client.Write(socksConnectRequestDomain("example.com", 443)); err != nil {
		t.Fatalf("write connect request: %v", err)
	}
	socksReply := make([]byte, 10)
	if _, err := io.ReadFull(client, socksReply); err != nil {
		t.Fatalf("read socks reply: %v", err)
	}
	if socksReply[1] != 0x00 {
		t.Fatalf("socks reply=%#x want success", socksReply[1])
	}
	select {
	case <-dialed:
	case <-time.After(time.Second):
		t.Fatal("upstream was not dialed")
	}

	server.close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after server close")
	}
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("client write succeeded after server close")
	}
}

func TestSOCKSIPv6TargetReturnsAddressTypeUnsupported(t *testing.T) {
	code := socksReplyCodeForRequest(t, socksConnectRequestIPv6(net.ParseIP("2001:db8::1"), 443))
	if code != 0x08 {
		t.Fatalf("IPv6 SOCKS reply=%#x want 0x08", code)
	}
}

func TestSOCKSGenericResolveFailureReturnsGeneralFailure(t *testing.T) {
	oldLookup := lookupSOCKSTargetHost
	lookupSOCKSTargetHost = func(context.Context, *netstacktun.Net, string) ([]string, error) {
		return nil, errors.New("resolver down")
	}
	defer func() { lookupSOCKSTargetHost = oldLookup }()

	code := socksReplyCodeForRequest(t, socksConnectRequestDomain("example.com", 443))
	if code != 0x05 {
		t.Fatalf("generic failure SOCKS reply=%#x want 0x05", code)
	}
}

func socksReplyCodeForRequest(t *testing.T, request []byte) byte {
	t.Helper()
	client, serverConn := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- (&socksServer{}).handle(context.Background(), serverConn) }()

	if _, err := client.Write([]byte{socksVersion5, 0x01, socksNoAuth}); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read handshake reply: %v", err)
	}
	if _, err := client.Write(request); err != nil {
		t.Fatalf("write connect request: %v", err)
	}
	socksReply := make([]byte, 10)
	if _, err := io.ReadFull(client, socksReply); err != nil {
		t.Fatalf("read socks reply: %v", err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("socks handler did not finish")
	}
	return socksReply[1]
}

func socksConnectRequestDomain(host string, port uint16) []byte {
	raw := []byte(host)
	req := []byte{socksVersion5, socksConnect, 0x00, 0x03, byte(len(raw))}
	req = append(req, raw...)
	req = append(req, byte(port>>8), byte(port))
	return req
}

func socksConnectRequestIPv6(ip net.IP, port uint16) []byte {
	raw := ip.To16()
	req := []byte{socksVersion5, socksConnect, 0x00, 0x04}
	req = append(req, raw...)
	req = append(req, byte(port>>8), byte(port))
	return req
}

type scriptedListener struct {
	calls atomic.Int32
	errs  []error
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	call := int(l.calls.Add(1)) - 1
	if call < len(l.errs) {
		return nil, l.errs[call]
	}
	return nil, net.ErrClosed
}

func (l *scriptedListener) Close() error {
	return nil
}

func (l *scriptedListener) Addr() net.Addr {
	return dummyAddr("scripted")
}

type temporaryNetError struct {
	err error
}

func (e temporaryNetError) Error() string {
	return e.err.Error()
}

func (e temporaryNetError) Timeout() bool {
	return false
}

func (e temporaryNetError) Temporary() bool {
	return true
}

type dummyAddr string

func (a dummyAddr) Network() string {
	return string(a)
}

func (a dummyAddr) String() string {
	return string(a)
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			acceptErr <- errors.New("accepted conn is not TCP")
			return
		}
		accepted <- tcp
	}()

	rawClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, ok := rawClient.(*net.TCPConn)
	if !ok {
		_ = rawClient.Close()
		t.Fatal("client conn is not TCP")
	}

	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErr:
		_ = client.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = client.Close()
		t.Fatal("accept timeout")
	}
	return nil, nil
}

func TestSOCKSUserPassAuthAcceptsValidCredentials(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- socksHandshake(serverConn, "user", "secret") }()

	if _, err := client.Write([]byte{socksVersion5, 0x02, socksNoAuth, socksUserPassAuth}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != socksUserPassAuth {
		t.Fatalf("selected method=%#x want username/password", reply[1])
	}
	if _, err := client.Write(socksUserPassRequest("user", "secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != socksUserPassVersion || reply[1] != 0x00 {
		t.Fatalf("auth reply=%v want success", reply)
	}
	if err := <-done; err != nil {
		t.Fatalf("handshake: %v", err)
	}
}

func TestSOCKSUserPassAuthRejectsWrongPassword(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- socksHandshake(serverConn, "user", "secret") }()

	if _, err := client.Write([]byte{socksVersion5, 0x01, socksUserPassAuth}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(socksUserPassRequest("user", "wrong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] == 0x00 {
		t.Fatal("wrong password accepted")
	}
	if err := <-done; err == nil {
		t.Fatal("handshake succeeded with wrong password")
	}
}

func TestSOCKSUserPassAuthRejectsNoAuthClient(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- socksHandshake(serverConn, "user", "secret") }()

	if _, err := client.Write([]byte{socksVersion5, 0x01, socksNoAuth}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != socksNoAcceptableAuth {
		t.Fatalf("method=%#x want 0xff", reply[1])
	}
	if err := <-done; err == nil {
		t.Fatal("no-auth client accepted when credentials are configured")
	}
}

func TestSOCKSServerRejectsConnectionsOverLimit(t *testing.T) {
	server, err := startSOCKSServer(socksOptions{listen: "127.0.0.1:0", maxConns: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.close()

	first, err := net.Dial("tcp", server.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write([]byte{socksVersion5, 0x01, socksNoAuth}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(first, reply); err != nil {
		t.Fatalf("first connection handshake: %v", err)
	}

	second, err := net.Dial("tcp", server.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection over limit was served")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection over limit was left open")
	}

	_ = first.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		third, err := net.Dial("tcp", server.addr())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = third.Write([]byte{socksVersion5, 0x01, socksNoAuth})
		_ = third.SetReadDeadline(time.Now().Add(time.Second))
		_, err = io.ReadFull(third, reply)
		_ = third.Close()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot was not released after first connection closed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProxyDeadlinesAreThrottled(t *testing.T) {
	left := &deadlineCountingConn{}
	right := &deadlineCountingConn{}
	d := newProxyDeadlines(left, right, time.Minute)
	for i := 0; i < 1000; i++ {
		d.touchRead()
		d.touchWrite(left)
		d.touchWrite(right)
	}
	if got := left.reads.Load(); got != 1 {
		t.Fatalf("left SetReadDeadline calls=%d want 1", got)
	}
	if got := left.writes.Load(); got != 1 {
		t.Fatalf("left SetWriteDeadline calls=%d want 1", got)
	}
	if got := right.writes.Load(); got != 1 {
		t.Fatalf("right SetWriteDeadline calls=%d want 1", got)
	}
	d.lastRead.Store(time.Now().Add(-2 * time.Second).UnixNano())
	d.touchRead()
	if got := right.reads.Load(); got != 2 {
		t.Fatalf("right SetReadDeadline calls=%d want 2 after refresh interval", got)
	}
}

func TestSOCKSProxyActiveSessionOutlivesIdleTimeout(t *testing.T) {
	oldIdle := socksProxyIdleTimeout
	socksProxyIdleTimeout = 200 * time.Millisecond
	defer func() { socksProxyIdleTimeout = oldIdle }()

	leftClient, leftProxy := tcpPair(t)
	rightClient, rightProxy := tcpPair(t)
	defer leftClient.Close()
	defer rightClient.Close()
	go func() { _ = proxy(context.Background(), leftProxy, rightProxy) }()

	buf := make([]byte, 1)
	for i := 0; i < 20; i++ {
		if _, err := leftClient.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		_ = rightClient.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(rightClient, buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func socksUserPassRequest(username, password string) []byte {
	req := []byte{socksUserPassVersion, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	return append(req, password...)
}

type deadlineCountingConn struct {
	net.Conn
	reads  atomic.Int32
	writes atomic.Int32
}

func (c *deadlineCountingConn) SetReadDeadline(time.Time) error {
	c.reads.Add(1)
	return nil
}

func (c *deadlineCountingConn) SetWriteDeadline(time.Time) error {
	c.writes.Add(1)
	return nil
}
