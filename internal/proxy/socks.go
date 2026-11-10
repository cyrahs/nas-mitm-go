package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ServeSOCKS5 accepts SOCKS5 CONNECT requests and hands each one to the HTTP
// proxy at httpProxy as an HTTP CONNECT, so both entrances share one set of
// interception rules. Suwayomi can only speak SOCKS5: the JVM's
// socksProxyHost setting is what every client in it, the extension's
// included, picks up.
func ServeSOCKS5(ctx context.Context, listener net.Listener, httpProxy string, logger *slog.Logger) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		go func() {
			if err := serveSOCKS5Conn(conn, httpProxy); err != nil && !errors.Is(err, io.EOF) {
				logger.Debug("socks5 connection ended", "error", err)
			}
		}()
	}
}

const (
	socksVersion   = 5
	socksNoAuth    = 0
	socksNoMethods = 0xff
	socksConnect   = 1
	atypIPv4       = 1
	atypDomain     = 3
	atypIPv6       = 4

	replySucceeded       = 0
	replyGeneralFailure  = 1
	replyHostUnreachable = 4
	replyCmdUnsupported  = 7
	replyAtypUnsupported = 8
)

func serveSOCKS5Conn(client net.Conn, httpProxy string) error {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(client)

	// Greeting: version, method count, methods.
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != socksVersion {
		return fmt.Errorf("not SOCKS5 (version %d)", header[0])
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	noAuth := false
	for _, m := range methods {
		if m == socksNoAuth {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = client.Write([]byte{socksVersion, socksNoMethods})
		return errors.New("client offered no acceptable auth method")
	}
	if _, err := client.Write([]byte{socksVersion, socksNoAuth}); err != nil {
		return err
	}

	// Request: version, command, reserved, address type, address, port.
	request := make([]byte, 4)
	if _, err := io.ReadFull(reader, request); err != nil {
		return err
	}
	if request[1] != socksConnect {
		_ = reply(client, replyCmdUnsupported)
		return fmt.Errorf("unsupported SOCKS command %d", request[1])
	}
	var host string
	switch request[3] {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return err
		}
		host = net.IP(addr).String()
	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return err
		}
		host = net.IP(addr).String()
	case atypDomain:
		length, err := reader.ReadByte()
		if err != nil {
			return err
		}
		name := make([]byte, length)
		if _, err := io.ReadFull(reader, name); err != nil {
			return err
		}
		host = string(name)
	default:
		_ = reply(client, replyAtypUnsupported)
		return fmt.Errorf("unsupported address type %d", request[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return err
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))

	// A client that resolved the name itself sends only an address, and
	// interception is decided by name. Answer first, then read the name the
	// client puts in its TLS ClientHello.
	answered := false
	if net.ParseIP(host) != nil {
		if err := reply(client, replySucceeded); err != nil {
			return err
		}
		answered = true
		if sni := peekSNI(reader); sni != "" {
			host = sni
		}
	}
	target := net.JoinHostPort(host, port)

	upstream, err := net.DialTimeout("tcp", httpProxy, 10*time.Second)
	if err != nil {
		if !answered {
			_ = reply(client, replyGeneralFailure)
		}
		return err
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprintf(upstream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		if !answered {
			_ = reply(client, replyGeneralFailure)
		}
		return err
	}
	upstreamReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamReader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		if !answered {
			_ = reply(client, replyGeneralFailure)
		}
		return err
	}
	if resp.StatusCode != http.StatusOK {
		if !answered {
			_ = reply(client, replyHostUnreachable)
		}
		return fmt.Errorf("CONNECT %s: %s", target, resp.Status)
	}
	if !answered {
		if err := reply(client, replySucceeded); err != nil {
			return err
		}
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	// Bytes either side already buffered must go first.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, reader)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstreamReader)
		closeWrite(client)
	}()
	wg.Wait()
	return nil
}

func reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{socksVersion, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	_ = conn.Close()
}

// peekSNI returns the server name from a TLS ClientHello at the head of r
// without consuming it, or "" when there is none.
func peekSNI(r *bufio.Reader) string {
	header, err := r.Peek(5)
	if err != nil || header[0] != 0x16 {
		return ""
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length > r.Size()-5 {
		length = r.Size() - 5
	}
	record, err := r.Peek(5 + length)
	if err != nil {
		return ""
	}
	return parseSNI(record[5:])
}

// parseSNI reads the server_name extension of a ClientHello handshake message.
func parseSNI(b []byte) string {
	// handshake type (1 = ClientHello), 3-byte length, version, random.
	if len(b) < 38 || b[0] != 1 {
		return ""
	}
	b = b[38:]
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(b[i])
		}
		if len(b) < lenBytes+n {
			return false
		}
		b = b[lenBytes+n:]
		return true
	}
	// session id, cipher suites, compression methods.
	if !skip(1) || !skip(2) || !skip(1) || len(b) < 2 {
		return ""
	}
	b = b[2:] // extensions length
	for len(b) >= 4 {
		extType := binary.BigEndian.Uint16(b[0:2])
		extLen := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < 4+extLen {
			return ""
		}
		data := b[4 : 4+extLen]
		b = b[4+extLen:]
		if extType != 0 || len(data) < 2 {
			continue
		}
		list := data[2:]
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:3]))
			if len(list) < 3+nameLen {
				return ""
			}
			if nameType == 0 {
				return string(list[3 : 3+nameLen])
			}
			list = list[3+nameLen:]
		}
	}
	return ""
}
