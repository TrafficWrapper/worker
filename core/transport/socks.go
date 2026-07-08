package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	netstacktun "github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

const (
	socksVersion5               = 0x05
	socksNoAuth                 = 0x00
	socksConnect                = 0x01
	socksProxyBufferLen         = 256 * 1024
	socksShutdownGrace          = 2 * time.Second
	socksClientHandshakeTimeout = 45 * time.Second
	socksUpstreamDialTimeout    = 30 * time.Second
)

var (
	socksAcceptBackoffMin = 50 * time.Millisecond
	socksAcceptBackoffMax = 200 * time.Millisecond
	socksProxyIdleTimeout = 3 * time.Minute
)

var socksProxyBuffers = sync.Pool{
	New: func() any {
		buf := make([]byte, socksProxyBufferLen)
		return &buf
	},
}

type socksServer struct {
	listener net.Listener
	tnet     *netstacktun.Net
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func startSOCKSServer(listen string, tnet *netstacktun.Net) (*socksServer, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("listen socks %s: %w", listen, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &socksServer{listener: ln, tnet: tnet, ctx: ctx, cancel: cancel}
	server.wg.Add(1)
	go server.serve(ctx)
	return server, nil
}

func (s *socksServer) addr() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *socksServer) close() {
	if s == nil {
		return
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.wg.Wait()
}

func (s *socksServer) serve(ctx context.Context) {
	defer s.wg.Done()
	backoff := socksAcceptBackoffMin
	for {
		client, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			if isTemporaryAcceptError(err) {
				log.Printf("transport: socks accept temporary error: %v", err)
				timer := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				backoff *= 2
				if backoff > socksAcceptBackoffMax {
					backoff = socksAcceptBackoffMax
				}
				continue
			}
			log.Printf("transport: socks accept stopped after permanent error: %v", err)
			return
		}
		backoff = socksAcceptBackoffMin
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.handle(ctx, client)
		}()
	}
}

func (s *socksServer) handle(ctx context.Context, client net.Conn) error {
	defer client.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.SetDeadline(time.Now().Add(socksShutdownGrace))
			_ = client.Close()
		case <-done:
		}
	}()
	defer close(done)
	tuneConn(client)
	if err := client.SetDeadline(time.Now().Add(socksClientHandshakeTimeout)); err != nil {
		return err
	}
	if err := socksHandshake(client); err != nil {
		return err
	}
	target, err := readSOCKSConnect(client)
	if err != nil {
		_ = writeSOCKSReply(client, 0x07)
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, socksUpstreamDialTimeout)
	defer cancel()
	upstream, err := s.dial(dialCtx, target)
	if err != nil {
		if errors.Is(err, errUnsupportedAddrType) {
			log.Printf("transport: socks refused IPv6/unsupported %q (fail-closed)", target.host)
			_ = writeSOCKSReply(client, 0x08)
		} else {
			_ = writeSOCKSReply(client, 0x05)
		}
		return err
	}
	defer upstream.Close()
	tuneConn(upstream)
	if err := writeSOCKSReply(client, 0x00); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	return proxy(ctx, client, upstream)
}

func socksHandshake(rw io.ReadWriter) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(rw, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 {
		return fmt.Errorf("unsupported socks version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(rw, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == socksNoAuth {
			_, err := rw.Write([]byte{socksVersion5, socksNoAuth})
			return err
		}
	}
	_, _ = rw.Write([]byte{socksVersion5, 0xff})
	return errors.New("socks client offered no no-auth method")
}

type socksTarget struct {
	host string
	port uint16
}

func readSOCKSConnect(r io.Reader) (socksTarget, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return socksTarget{}, err
	}
	if header[0] != socksVersion5 {
		return socksTarget{}, fmt.Errorf("unsupported socks request version %d", header[0])
	}
	if header[1] != socksConnect {
		return socksTarget{}, fmt.Errorf("unsupported socks command %d", header[1])
	}
	var host string
	switch header[3] {
	case 0x01:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(r, raw); err != nil {
			return socksTarget{}, err
		}
		host = net.IP(raw).String()
	case 0x03:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return socksTarget{}, err
		}
		raw := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, raw); err != nil {
			return socksTarget{}, err
		}
		host = string(raw)
	case 0x04:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(r, raw); err != nil {
			return socksTarget{}, err
		}
		host = net.IP(raw).String()
	default:
		return socksTarget{}, fmt.Errorf("unsupported socks atyp %d", header[3])
	}
	var portRaw [2]byte
	if _, err := io.ReadFull(r, portRaw[:]); err != nil {
		return socksTarget{}, err
	}
	return socksTarget{host: host, port: binary.BigEndian.Uint16(portRaw[:])}, nil
}

func (s *socksServer) dial(ctx context.Context, target socksTarget) (net.Conn, error) {
	addr, err := resolveTarget(ctx, s.tnet, target)
	if err != nil {
		return nil, err
	}
	return dialSOCKSTargetTCP(ctx, s.tnet, addr)
}

var lookupSOCKSTargetHost = func(ctx context.Context, tnet *netstacktun.Net, host string) ([]string, error) {
	if tnet == nil {
		return nil, errors.New("netstack resolver is unavailable")
	}
	return tnet.LookupContextHost(ctx, host)
}

var dialSOCKSTargetTCP = func(ctx context.Context, tnet *netstacktun.Net, addr netip.AddrPort) (net.Conn, error) {
	if tnet == nil {
		return nil, errors.New("netstack dialer is unavailable")
	}
	return tnet.DialContextTCPAddrPort(ctx, addr)
}

var errUnsupportedAddrType = errors.New("unsupported address type")

func resolveTarget(ctx context.Context, tnet *netstacktun.Net, target socksTarget) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(target.host); err == nil {
		if ip.Is4() {
			return netip.AddrPortFrom(ip, target.port), nil
		}
		return netip.AddrPort{}, fmt.Errorf("%w: IPv6 target is not supported without IPv6 local address: %s", errUnsupportedAddrType, target.host)
	}
	addrs, err := lookupSOCKSTargetHost(ctx, tnet, target.host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, addr := range addrs {
		ip, err := netip.ParseAddr(addr)
		if err == nil && ip.Is4() {
			return netip.AddrPortFrom(ip, target.port), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("%w: no IPv4 address for %s", errUnsupportedAddrType, target.host)
}

func writeSOCKSReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{socksVersion5, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func proxy(ctx context.Context, left, right net.Conn) error {
	deadlines := newProxyDeadlines(left, right, socksProxyIdleTimeout)
	deadlines.touchRead()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			deadline := time.Now().Add(socksShutdownGrace)
			_ = left.SetDeadline(deadline)
			_ = right.SetDeadline(deadline)
			_ = left.Close()
			_ = right.Close()
		case <-done:
		}
	}()
	defer close(done)
	type copyResult struct {
		dst net.Conn
		err error
	}
	errCh := make(chan copyResult, 2)
	copyConn := func(dst, src net.Conn) {
		bufPtr := socksProxyBuffers.Get().(*[]byte)
		defer socksProxyBuffers.Put(bufPtr)
		errCh <- copyResult{dst: dst, err: copyConnWithIdle(dst, src, *bufPtr, deadlines)}
	}
	go copyConn(left, right)
	go copyConn(right, left)

	var firstErr error
	for i := 0; i < 2; i++ {
		result := <-errCh
		if firstErr == nil && result.err != nil && !isExpectedProxyClose(result.err) {
			firstErr = result.err
		}
		halfCloseWrite(result.dst)
	}
	_ = left.Close()
	_ = right.Close()
	return firstErr
}

func tuneConn(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetReadBuffer(socksProxyBufferLen)
		_ = tcp.SetWriteBuffer(socksProxyBufferLen)
		return
	}
	type bufferTuner interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}
	if tuned, ok := conn.(bufferTuner); ok {
		_ = tuned.SetReadBuffer(socksProxyBufferLen)
		_ = tuned.SetWriteBuffer(socksProxyBufferLen)
	}
}

func (target socksTarget) String() string {
	return net.JoinHostPort(target.host, strconv.Itoa(int(target.port)))
}

func isTemporaryAcceptError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "too many open files") || strings.Contains(text, "temporary")
}

type proxyDeadlines struct {
	conns []net.Conn
	idle  time.Duration
}

func newProxyDeadlines(left, right net.Conn, idle time.Duration) proxyDeadlines {
	return proxyDeadlines{conns: []net.Conn{left, right}, idle: idle}
}

func (d proxyDeadlines) touchRead() {
	if d.idle <= 0 {
		return
	}
	deadline := time.Now().Add(d.idle)
	for _, conn := range d.conns {
		_ = conn.SetReadDeadline(deadline)
	}
}

func (d proxyDeadlines) touchWrite(conn net.Conn) {
	if d.idle <= 0 {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(d.idle))
}

func copyConnWithIdle(dst, src net.Conn, buf []byte, deadlines proxyDeadlines) error {
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			deadlines.touchRead()
			if err := writeAllWithIdle(dst, buf[:n], deadlines); err != nil {
				return err
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

func writeAllWithIdle(dst net.Conn, data []byte, deadlines proxyDeadlines) error {
	for len(data) > 0 {
		deadlines.touchWrite(dst)
		n, err := dst.Write(data)
		if n > 0 {
			data = data[n:]
			deadlines.touchRead()
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func halfCloseWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func isExpectedProxyClose(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}
