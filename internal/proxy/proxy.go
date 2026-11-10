// Package proxy assembles the intercepting proxy: an HTTP proxy built on
// goproxy, optionally fronted by a SOCKS5 listener, that decrypts only the
// hosts a handler claims and passes every other connection through untouched.
package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/cyrahs/nas-mitm-go/internal/ca"
	"github.com/cyrahs/nas-mitm-go/internal/flow"
	"github.com/cyrahs/nas-mitm-go/internal/httpx"
)

// Options configure New.
type Options struct {
	Authority *ca.Authority
	Handlers  []flow.Handler
	// Upstream is the transport for requests the handlers let through.
	// Nil means a direct connection that verifies certificates.
	Upstream *http.Transport
	// InterceptPorts are the CONNECT ports of a claimed host that are
	// intercepted, ["443"] by default. Other ports are tunnelled as they are.
	// Plain HTTP inside a CONNECT (port 80) is intercepted too when listed.
	InterceptPorts []string
	// ConnectDial dials tunnelled (not intercepted) CONNECT targets. Nil
	// means a direct connection. Tests use it to stay off the network.
	ConnectDial func(network, addr string) (net.Conn, error)
	Logger      *slog.Logger
}

// New returns the HTTP proxy handler.
func New(opts Options) *goproxy.ProxyHttpServer {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ports := opts.InterceptPorts
	if len(ports) == 0 {
		ports = []string{"443"}
	}

	server := goproxy.NewProxyHttpServer()
	server.Logger = log.New(&slogWriter{logger}, "", 0)
	server.Verbose = false
	// goproxy's default transport skips certificate verification and honours
	// the environment's proxy; neither is wanted here.
	if opts.Upstream != nil {
		server.Tr = opts.Upstream
	} else {
		server.Tr, _ = httpx.Transport("", true)
	}

	if opts.ConnectDial != nil {
		server.ConnectDial = opts.ConnectDial
	} else {
		server.ConnectDial = nil
	}

	handlerFor := func(host string) flow.Handler {
		for _, h := range opts.Handlers {
			if flow.SiteOf(host, h.Hosts()) != "" {
				return h
			}
		}
		return nil
	}

	mitm := &goproxy.ConnectAction{
		Action: goproxy.ConnectMitm,
		TLSConfig: func(host string, _ *goproxy.ProxyCtx) (*tls.Config, error) {
			return opts.Authority.TLSConfig(stripPort(host))
		},
	}
	server.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		hostname, hostPort, err := net.SplitHostPort(host)
		if err != nil {
			hostname, hostPort = host, "443"
		}
		if slices.Contains(ports, hostPort) && handlerFor(hostname) != nil {
			return mitm, host
		}
		return goproxy.OkConnect, host
	})

	server.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		state := &flow.State{Handler: handlerFor(req.URL.Hostname())}
		ctx.UserData = state
		if state.Handler == nil {
			return req, nil
		}
		next, resp := state.Handler.Request(req, ctx)
		if resp != nil {
			state.Synthetic = true
		}
		return next, resp
	})

	server.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		state, ok := ctx.UserData.(*flow.State)
		if resp == nil || !ok || state.Handler == nil || state.Synthetic {
			return resp
		}
		return state.Handler.Response(resp, ctx)
	})

	return server
}

func stripPort(host string) string {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		return hostname
	}
	return host
}

// slogWriter routes goproxy's own log lines (warnings only, since Verbose is
// off) into the structured log.
type slogWriter struct{ logger *slog.Logger }

func (w *slogWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	// A client that drops a kept-alive connection is routine, not a warning.
	if strings.Contains(line, "Cannot read request from mitm'd client") && strings.Contains(line, io.ErrUnexpectedEOF.Error()) {
		return len(p), nil
	}
	w.logger.Warn(line, "source", "goproxy")
	return len(p), nil
}
