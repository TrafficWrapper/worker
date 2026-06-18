package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	netstacktun "github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

const (
	socksVersion5       = 0x05
	socksNoAuth         = 0x00
	socksConnect        = 0x01
	socksProxyBufferLen = 256 * 1024
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
	wg       sync.WaitGroup
}

func startSOCKSServer(listen string, tnet *netstacktun.Net) (*socksServer, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("listen socks %s: %w", listen, err)
	}
	server := &socksServer{listener: ln, tnet: tnet}
	server.wg.Add(1)
	go server.serve()
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
	if s.listener != nil {
		_ = s.listener.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (s *socksServer) serve() {
	defer s.wg.Done()
	for {
		client, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.handle(client)
		}()
	}
}

func (s *socksServer) handle(client net.Conn) error {
	defer client.Close()
	tuneConn(client)
	if err := client.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream, err := s.dial(ctx, target)
	if err != nil {
		_ = writeSOCKSReply(client, 0x05)
		return err
	}
	defer upstream.Close()
	tuneConn(upstream)
	if err := writeSOCKSReply(client, 0x00); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	return proxy(client, upstream)
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
	addr, err := resolveTarget(ctx, target)
	if err != nil {
		return nil, err
	}
	return s.tnet.DialContextTCPAddrPort(ctx, addr)
}

func resolveTarget(ctx context.Context, target socksTarget) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(target.host); err == nil {
		if ip.Is4() {
			return netip.AddrPortFrom(ip, target.port), nil
		}
		return netip.AddrPort{}, fmt.Errorf("IPv6 target is not supported without IPv6 local address: %s", target.host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, target.host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, addr := range addrs {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if ok && ip.Is4() {
			return netip.AddrPortFrom(ip, target.port), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("no IPv4 address for %s", target.host)
}

func writeSOCKSReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{socksVersion5, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func proxy(left, right net.Conn) error {
	errCh := make(chan error, 2)
	copyConn := func(dst, src net.Conn) {
		bufPtr := socksProxyBuffers.Get().(*[]byte)
		defer socksProxyBuffers.Put(bufPtr)
		_, err := io.CopyBuffer(dst, src, *bufPtr)
		errCh <- err
	}
	go copyConn(left, right)
	go copyConn(right, left)
	err := <-errCh
	_ = left.Close()
	_ = right.Close()
	<-errCh
	return err
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
