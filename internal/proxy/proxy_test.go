package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	xproxy "golang.org/x/net/proxy"

	"github.com/cyrahs/nas-mitm-go/internal/ca"
	"github.com/cyrahs/nas-mitm-go/internal/flow"
	"github.com/cyrahs/nas-mitm-go/internal/httpx"
)

// stub claims intercept.test: it answers /local itself, tags what it lets
// through, and records what the origin answered.
type stub struct {
	mu        sync.Mutex
	responses []int
}

func (s *stub) Name() string    { return "stub" }
func (s *stub) Hosts() []string { return []string{"intercept.test"} }
func (s *stub) Request(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Path == "/local" {
		return req, httpx.Text(req, http.StatusTeapot, "text/plain", []byte("answered by the handler"))
	}
	req.Header.Set("X-Intercepted", "yes")
	return req, nil
}
func (s *stub) Response(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
	s.mu.Lock()
	s.responses = append(s.responses, resp.StatusCode)
	s.mu.Unlock()
	resp.Header.Set("X-Seen", "yes")
	return resp
}

type harness struct {
	origin    *httptest.Server
	stub      *stub
	authority *ca.Authority
	httpAddr  string
	socksAddr string
}

func setup(t *testing.T) *harness {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Saw", r.Header.Get("X-Intercepted"))
		_, _ = io.WriteString(w, "origin "+r.Host+r.URL.Path)
	}))
	t.Cleanup(origin.Close)

	dir := t.TempDir()
	if err := ca.Generate(dir); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Every name resolves to the origin; it presents its own test
	// certificate, which upstream trusts under the name example.com.
	originAddr := origin.Listener.Addr().String()
	dial := func(_ context.Context, network, _ string) (net.Conn, error) {
		return net.Dial(network, originAddr)
	}
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(origin.Certificate())
	upstream := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: upstreamRoots, ServerName: "example.com"}}

	s := &stub{}
	handler := New(Options{
		Authority: authority,
		Handlers:  []flow.Handler{s},
		Upstream:  upstream,
		ConnectDial: func(network, _ string) (net.Conn, error) {
			return net.Dial(network, originAddr)
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(httpListener) }()
	t.Cleanup(func() { _ = server.Close() })

	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = ServeSOCKS5(ctx, socksListener, httpListener.Addr().String(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	return &harness{origin: origin, stub: s, authority: authority, httpAddr: httpListener.Addr().String(), socksAddr: socksListener.Addr().String()}
}

// client trusts both the Pod CA and the origin's own certificate, so a
// passed-through tunnel and an intercepted one both verify; which of the two
// signed the leaf tells them apart.
func (h *harness) client(t *testing.T, viaSOCKS bool) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(h.authority.Certificate())
	roots.AddCert(h.origin.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true}
	if viaSOCKS {
		dialer, err := xproxy.SOCKS5("tcp", h.socksAddr, nil, xproxy.Direct)
		if err != nil {
			t.Fatal(err)
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.(xproxy.ContextDialer).DialContext(ctx, network, addr)
		}
	} else {
		proxyURL, _ := url.Parse("http://" + h.httpAddr)
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func get(t *testing.T, client *http.Client, target string) (*http.Response, string) {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func signedByPodCA(resp *http.Response) bool {
	return resp.TLS != nil && resp.TLS.PeerCertificates[0].Issuer.CommonName == "nas-mitm Pod CA"
}

func TestInterceptAndPassThrough(t *testing.T) {
	h := setup(t)
	for _, viaSOCKS := range []bool{false, true} {
		name := "http-connect"
		if viaSOCKS {
			name = "socks5"
		}
		t.Run(name, func(t *testing.T) {
			client := h.client(t, viaSOCKS)

			// A claimed host on 443 is decrypted and rewritten.
			resp, body := get(t, client, "https://intercept.test/page")
			if !signedByPodCA(resp) {
				t.Fatal("claimed host was not intercepted")
			}
			if resp.Proto != "HTTP/1.1" {
				t.Fatalf("negotiated %s, want HTTP/1.1", resp.Proto)
			}
			if resp.Header.Get("X-Origin-Saw") != "yes" || resp.Header.Get("X-Seen") != "yes" || body != "origin intercept.test/page" {
				t.Fatalf("headers %v body %q", resp.Header, body)
			}

			// A handler's own answer never reaches the origin or the response hook.
			before := len(h.stub.responses)
			resp, body = get(t, client, "https://intercept.test/local")
			if resp.StatusCode != http.StatusTeapot || body != "answered by the handler" || resp.Header.Get("X-Seen") != "" {
				t.Fatalf("local answer %d %q %v", resp.StatusCode, body, resp.Header)
			}
			if len(h.stub.responses) != before {
				t.Fatal("response hook ran on a handler's own answer")
			}

			// Anything else is tunnelled untouched, with the origin's certificate.
			resp, body = get(t, client, "https://example.com/other")
			if signedByPodCA(resp) {
				t.Fatal("unclaimed host was intercepted")
			}
			if resp.Header.Get("X-Origin-Saw") != "" || !strings.HasPrefix(body, "origin example.com") {
				t.Fatalf("passthrough headers %v body %q", resp.Header, body)
			}
		})
	}
}

// A claimed host on another port is tunnelled, as mitmproxy's
// --allow-hosts '...:443$' did.
func TestOtherPortsOfAClaimedHostPassThrough(t *testing.T) {
	h := setup(t)
	client := h.client(t, true)
	// The origin's certificate does not name intercept.test, so a verified
	// handshake failing on exactly that is the proof it was tunnelled.
	_, err := client.Get("https://intercept.test:8443/x")
	if err == nil || !strings.Contains(err.Error(), "not intercept.test") {
		t.Fatalf("want the origin's own certificate, got %v", err)
	}
}

// Plain HTTP sent inside a CONNECT (sing-box's HTTP outbound does this) is
// rewritten when port 80 is listed.
func TestPlainHTTPInsideConnect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "saw "+r.Header.Get("X-Intercepted"))
	}))
	defer origin.Close()
	dir := t.TempDir()
	_ = ca.Generate(dir)
	authority, _ := ca.Load(dir)
	upstream := &http.Transport{DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
		return net.Dial(network, origin.Listener.Addr().String())
	}}
	handler := New(Options{Authority: authority, Handlers: []flow.Handler{&stub{}}, Upstream: upstream,
		InterceptPorts: []string{"443", "80"}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "CONNECT intercept.test:80 HTTP/1.1\r\nHost: intercept.test:80\r\n\r\n")
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("CONNECT answered %q", buf[:n])
	}
	_, _ = io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: intercept.test\r\nConnection: close\r\n\r\n")
	all, _ := io.ReadAll(conn)
	if !strings.Contains(string(all), "saw yes") {
		t.Fatalf("response %q", all)
	}
}
