package transport

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
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
	server := &socksServer{listener: listener}
	server.wg.Add(1)
	server.serve()

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
	go func() { done <- proxy(leftProxy, rightProxy) }()

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
	go func() { proxyDone <- proxy(leftProxy, rightProxy) }()

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
