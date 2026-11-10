// Command nas-mitm is the intercepting proxy that sits beside RSSHub and
// Suwayomi in the home cluster, replacing mitmproxy and its Python addons.
//
//	nas-mitm gen-ca --dir /certs
//	nas-mitm run --certs /certs --listen 127.0.0.1:8080 --intercept-ports 443,80 --handlers flaresolverr,bilibili
//	nas-mitm run --certs /certs --socks5 0.0.0.0:1080 --handlers suwayomi
//	nas-mitm probe 127.0.0.1:1080
//	nas-mitm fetch --proxy http://exit:80 -H 'User-Agent: x' https://example.com/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cyrahs/nas-mitm-go/internal/bilibili"
	"github.com/cyrahs/nas-mitm-go/internal/ca"
	"github.com/cyrahs/nas-mitm-go/internal/flaresolverr"
	"github.com/cyrahs/nas-mitm-go/internal/flow"
	"github.com/cyrahs/nas-mitm-go/internal/httpx"
	"github.com/cyrahs/nas-mitm-go/internal/proxy"
	"github.com/cyrahs/nas-mitm-go/internal/suwayomi"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "gen-ca":
		err = genCA(os.Args[2:])
	case "run":
		err = run(os.Args[2:])
	case "probe":
		err = probe(os.Args[2:])
	case "fetch":
		err = fetch(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "nas-mitm:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nas-mitm gen-ca|run|probe|fetch [flags]")
	os.Exit(2)
}

func genCA(args []string) error {
	fs := flag.NewFlagSet("gen-ca", flag.ExitOnError)
	dir := fs.String("dir", "/certs", "directory to write ca.crt and ca.key into")
	_ = fs.Parse(args)
	if err := ca.Generate(*dir); err != nil {
		return err
	}
	fmt.Println("generated Pod-local CA in", *dir)
	return nil
}

// probe exits 0 when addr accepts a TCP connection: the readiness check, since
// the image has no shell.
func probe(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: nas-mitm probe HOST:PORT")
	}
	conn, err := net.DialTimeout("tcp", args[0], 5*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

type headerFlags []string

func (h *headerFlags) String() string     { return strings.Join(*h, ", ") }
func (h *headerFlags) Set(v string) error { *h = append(*h, v); return nil }

// fetch makes one GET with the same Go HTTP client the handlers use, so a
// site's reaction to it (a Cloudflare block, a risk-control code) can be
// checked from inside the cluster before a handler depends on it.
func fetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	proxyURL := fs.String("proxy", "", "HTTP proxy to go through (default direct)")
	var headers headerFlags
	fs.Var(&headers, "H", "request header 'Name: value' (repeatable)")
	limit := fs.Int("bytes", 300, "how much of the body to print")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: nas-mitm fetch [--proxy URL] [-H 'Name: value'] URL")
	}
	transport, err := httpx.Transport(*proxyURL, false)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, fs.Arg(0), nil)
	if err != nil {
		return err
	}
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return fmt.Errorf("bad header %q", h)
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	started := time.Now()
	resp, err := (&http.Client{Transport: transport, Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if decoded, err := httpx.Decode(body, resp.Header.Get("Content-Encoding")); err == nil {
		body = decoded
	}
	fmt.Printf("%s in %v, %d bytes, %s\n", resp.Status, time.Since(started).Round(time.Millisecond), len(body), resp.Proto)
	for _, name := range []string{"Content-Type", "Server", "Cf-Mitigated", "Cf-Ray"} {
		if v := resp.Header.Get(name); v != "" {
			fmt.Printf("%s: %s\n", name, v)
		}
	}
	if len(body) > *limit {
		body = body[:*limit]
	}
	fmt.Println(string(body))
	return nil
}

type starter interface{ Start(context.Context) }

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	certs := fs.String("certs", "/certs", "directory holding ca.crt and ca.key")
	listen := fs.String("listen", "", "HTTP proxy address (default: loopback, random port, when --socks5 is set)")
	socks := fs.String("socks5", "", "SOCKS5 listen address (optional)")
	handlerNames := fs.String("handlers", "", "comma-separated: suwayomi, flaresolverr, bilibili")
	ports := fs.String("intercept-ports", "443", "comma-separated CONNECT ports of a claimed host to intercept")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	_ = fs.Parse(args)

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	authority, err := ca.Load(*certs)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	var handlers []flow.Handler
	for _, name := range strings.Split(*handlerNames, ",") {
		switch strings.TrimSpace(name) {
		case "":
		case "suwayomi":
			handlers = append(handlers, suwayomi.New(suwayomi.ConfigFromEnv(), logger))
		case "flaresolverr":
			h, err := flaresolverr.New(flaresolverr.ConfigFromEnv(), logger)
			if err != nil {
				return err
			}
			handlers = append(handlers, h)
		case "bilibili":
			h, err := bilibili.New(bilibili.ConfigFromEnv(), logger)
			if err != nil {
				return err
			}
			handlers = append(handlers, h)
		default:
			return fmt.Errorf("unknown handler %q", name)
		}
	}
	if len(handlers) == 0 {
		return errors.New("no handlers given")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for _, h := range handlers {
		if s, ok := h.(starter); ok {
			s.Start(ctx)
		}
	}

	httpAddr := *listen
	if httpAddr == "" {
		if *socks == "" {
			return errors.New("give --listen, --socks5 or both")
		}
		httpAddr = "127.0.0.1:0"
	}
	httpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: proxy.New(proxy.Options{
			Authority:      authority,
			Handlers:       handlers,
			InterceptPorts: strings.Split(*ports, ","),
			Logger:         logger,
		}),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errs := make(chan error, 2)
	go func() { errs <- server.Serve(httpListener) }()

	names := make([]string, len(handlers))
	for i, h := range handlers {
		names[i] = h.Name()
	}
	attrs := []any{"http", httpListener.Addr().String(), "handlers", names}

	if *socks != "" {
		socksListener, err := net.Listen("tcp", *socks)
		if err != nil {
			return err
		}
		attrs = append(attrs, "socks5", socksListener.Addr().String())
		go func() { errs <- proxy.ServeSOCKS5(ctx, socksListener, httpListener.Addr().String(), logger) }()
	}
	logger.Info("nas-mitm listening", attrs...)

	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	return nil
}
