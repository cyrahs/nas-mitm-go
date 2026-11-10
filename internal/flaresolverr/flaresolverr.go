// Package flaresolverr serves browser-only sites out of FlareSolverr instead
// of fetching them directly.
//
// RSSHub's routes use plain HTTP clients, so they cannot answer a Cloudflare
// challenge, and nothing can be injected into a CONNECT tunnel from the
// outside. sing-box routes the hosts below here instead; the TLS is
// terminated with the Pod-local CA and the page is got one of two ways.
//
// The first request for a site goes to FlareSolverr, whose browser clears the
// challenge, and the clearance cookie and the user agent it was issued to are
// kept. Every later request is then a plain fetch carrying those two -- no
// browser, and no second challenge. That matters because the routes fan out:
// javlibrary's does Promise.all over every item on the list page, so a naive
// one-solve-per-request proxy fires thirty-odd challenges within a second and
// Cloudflare rate-limits the address rather than serving them. It also keeps
// each fetch well inside RSSHub's 30s REQUEST_TIMEOUT, which a queue of 11s
// solves would not.
//
// Requests that arrive while the first solve is still running wait on it and
// then take the fast path, so a cold fan-out costs one solve, not thirty.
//
// The browser session binds its proxy when Chrome starts. If the residential
// proxy behind the stable Service is replaced, Chrome can keep a dead
// connection and report ERR_PROXY_CONNECTION_FAILED even though the Service
// is healthy again. A failed solve therefore destroys and recreates the
// session once, which re-resolves the Service and binds a fresh browser to
// the current proxy backend. The request is retried once after repair; a
// still-broken proxy fails closed instead of causing an infinite recreate
// loop.
//
// Cloudflare rotates the clearance rather than holding it still, handing back
// a new value in Set-Cookie as it goes, so responses are harvested for one.
// Without that the stored cookie goes stale on rotation and the next request
// is challenged -- which showed up in production as an unmistakable rhythm:
// the first request of each round succeeded and the one right behind it got a
// 403, every 40 to 60 minutes.
//
// A request challenged anyway is retried once: drop the clearance, get a good
// one, and answer from that rather than handing the challenge page back to
// RSSHub. Only the first of a concurrent batch pays for a solve; the rest
// wait on the same lock and then simply re-fetch with what it earned.
//
// Cloudflare stopped issuing clearance to this cluster's addresses: a solve
// from a Netcup address burns the full 60s timeout and fails, while the same
// solve through a residential exit clears in about 13s. So every request to a
// solved site -- the solve, the replay, and the re-fetch -- leaves through
// ExitProxy. They have to agree, because Cloudflare binds the clearance to
// the address that earned it.
//
// To add a site: put its suffix in SOLVED_HOSTS and point a sing-box rule at
// the mitm outbound. Nothing else changes.
//
// This is a port of the mitmproxy addon that lived in nas-gitops
// (apps/rss/rsshub/mitmproxy/flaresolverr.py).
package flaresolverr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/cyrahs/nas-mitm-go/internal/env"
	"github.com/cyrahs/nas-mitm-go/internal/flow"
	"github.com/cyrahs/nas-mitm-go/internal/httpx"
)

// Config holds the tunables.
type Config struct {
	Hosts        []string
	FlareSolverr string
	// Every hop to a solved origin goes through here, so that the address
	// Cloudflare issued the clearance to is the one that comes back with it.
	// Empty means direct.
	ExitProxy string
	// One session, not one per site: a browser profile is expected to hold
	// cookies for many hosts, and every extra live session is another
	// resident Chrome.
	Session        string
	SolveTimeoutMS int
	HTTPTimeout    time.Duration
	ControlTimeout time.Duration
	RefetchTimeout time.Duration
	RepairAttempts int
	RepairCooldown time.Duration
}

// ConfigFromEnv reads the deployment's settings.
func ConfigFromEnv() Config {
	hosts := strings.FieldsFunc(env.String("SOLVED_HOSTS", "javlibrary.com"), func(r rune) bool { return r == ',' || r == ' ' })
	return Config{
		Hosts:          hosts,
		FlareSolverr:   env.String("FLARESOLVERR_URL", "http://flaresolverr.proxy.svc.cluster.local/v1"),
		ExitProxy:      env.String("SOLVER_EXIT_PROXY", ""),
		Session:        "rsshub",
		SolveTimeoutMS: 60000,
		HTTPTimeout:    90 * time.Second,
		ControlTimeout: 10 * time.Second,
		RefetchTimeout: 20 * time.Second,
		RepairAttempts: 1,
		RepairCooldown: 60 * time.Second,
	}
}

// Solution is FlareSolverr's answer to request.get.
type Solution struct {
	Status   int    `json:"status"`
	Response string `json:"response"`
	Cookies  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"cookies"`
	UserAgent string `json:"userAgent"`
}

// Answer is any FlareSolverr reply this handler reads.
type Answer struct {
	Solution *Solution `json:"solution"`
	Sessions []string  `json:"sessions"`
}

// HTTPError is a non-2xx reply from FlareSolverr, with its body.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body) }

// PostFunc sends one command to FlareSolverr.
type PostFunc func(payload map[string]any, timeout time.Duration) (*Answer, error)

// FetchFunc re-issues a request with clearance someone else earned. ok is
// false only when nothing came back at all.
type FetchFunc func(url string, held *Clearance) (status int, body []byte, ok bool)

// Clearance is what a solve earned for one site.
type Clearance struct {
	names     []string
	values    map[string]string
	UserAgent string
	earned    time.Time
}

func (c *Clearance) set(name, value string) {
	if _, ok := c.values[name]; !ok {
		c.names = append(c.names, name)
	}
	c.values[name] = value
}

// Header renders the cookies as a Cookie header value.
func (c *Clearance) Header() string {
	parts := make([]string, 0, len(c.names))
	for _, name := range c.names {
		parts = append(parts, name+"="+c.values[name])
	}
	return strings.Join(parts, "; ")
}

func (c *Clearance) clone() *Clearance {
	out := &Clearance{names: slices.Clone(c.names), values: make(map[string]string, len(c.values)), UserAgent: c.UserAgent, earned: c.earned}
	for k, v := range c.values {
		out.values[k] = v
	}
	return out
}

// Handler is the FlareSolverr detour.
type Handler struct {
	cfg    Config
	log    *slog.Logger
	post   PostFunc
	fetch  FetchFunc
	client *http.Client // to FlareSolverr itself
	exitRT goproxy.RoundTripper
	now    func() time.Time

	mu        sync.Mutex // guards clearance
	clearance map[string]*Clearance

	// solveMu queues callers so an expiry costs a single solve however many
	// requests tripped over it; it also guards the session state below.
	solveMu            sync.Mutex
	sessionReady       bool
	repairBlockedUntil time.Time
	lastRebuild        time.Time
}

// New returns the handler.
func New(cfg Config, logger *slog.Logger) (*Handler, error) {
	h := &Handler{
		cfg:       cfg,
		log:       logger.With("handler", "flaresolverr"),
		now:       time.Now,
		clearance: map[string]*Clearance{},
	}
	direct, err := httpx.Transport("", true)
	if err != nil {
		return nil, err
	}
	h.client = &http.Client{Transport: direct}
	h.post = h.postHTTP
	exit, err := httpx.Transport(cfg.ExitProxy, true)
	if err != nil {
		return nil, err
	}
	if cfg.ExitProxy != "" {
		h.exitRT = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			return exit.RoundTrip(req)
		})
	}
	refetch := &http.Client{Transport: exit, Timeout: cfg.RefetchTimeout}
	h.fetch = func(url string, held *Clearance) (int, []byte, bool) {
		return refetchWith(refetch, url, held, h.log)
	}
	h.log.Info("handler ready", "hosts", cfg.Hosts, "exit", orDirect(cfg.ExitProxy))
	return h, nil
}

func orDirect(proxy string) string {
	if proxy == "" {
		return "direct"
	}
	return proxy
}

func (h *Handler) Name() string    { return "flaresolverr" }
func (h *Handler) Hosts() []string { return h.cfg.Hosts }

func (h *Handler) postHTTP(payload map[string]any, timeout time.Duration) (*Answer, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.FlareSolverr, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, &HTTPError{Status: resp.StatusCode, Body: string(body)}
	}
	var answer Answer
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, err
	}
	return &answer, nil
}

// isProxyConnectionFailure identifies the Chrome failure a fresh
// proxy-bound session can repair.
//
// A session that no longer exists (FlareSolverr restarted, or someone
// destroyed it) is repaired the same way: by creating it again.
func isProxyConnectionFailure(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "err_proxy_connection_failed") || strings.Contains(text, "proxy connection failed") ||
		strings.Contains(text, "session doesn't exist") || strings.Contains(text, "session does not exist")
}

func (h *Handler) createPayload() map[string]any {
	// The proxy is fixed when the session is created rather than passed per
	// request: FlareSolverr starts the browser for the session, and a later
	// request cannot move an already-running browser onto a different exit.
	create := map[string]any{"cmd": "sessions.create", "session": h.cfg.Session}
	if h.cfg.ExitProxy != "" {
		create["proxy"] = map[string]any{"url": h.cfg.ExitProxy}
	}
	return create
}

// ensureSession keeps one browser alive so a solve does not also pay a cold
// Chrome start. Called with solveMu held.
func (h *Handler) ensureSession() bool {
	if h.sessionReady {
		return true
	}
	answer, err := h.post(map[string]any{"cmd": "sessions.list"}, h.cfg.ControlTimeout)
	if err == nil && !slices.Contains(answer.Sessions, h.cfg.Session) {
		_, err = h.post(h.createPayload(), h.cfg.ControlTimeout)
	}
	if err != nil {
		h.log.Warn("FlareSolverr session unavailable, falling back to a one-shot browser", "error", err)
		return false
	}
	h.sessionReady = true
	return true
}

// resetSession drops the browser so its proxy connection is resolved and
// bound again. Called with solveMu held.
func (h *Handler) resetSession() error {
	h.sessionReady = false
	h.mu.Lock()
	clear(h.clearance)
	h.mu.Unlock()

	// The session may already have disappeared with a FlareSolverr restart.
	// Only ignore that if the listing below proves it is gone.
	_, destroyErr := h.post(map[string]any{"cmd": "sessions.destroy", "session": h.cfg.Session}, h.cfg.ControlTimeout)

	answer, err := h.post(map[string]any{"cmd": "sessions.list"}, h.cfg.ControlTimeout)
	if err != nil {
		return err
	}
	if slices.Contains(answer.Sessions, h.cfg.Session) {
		return fmt.Errorf("FlareSolverr session %s survived destroy: %v", h.cfg.Session, destroyErr)
	}
	if _, err := h.post(h.createPayload(), h.cfg.ControlTimeout); err != nil {
		return err
	}
	h.sessionReady = true
	return nil
}

// solve asks FlareSolverr for the page. Called with solveMu held.
func (h *Handler) solve(url string) *Solution {
	if h.now().Before(h.repairBlockedUntil) {
		h.log.Warn("proxy-session repair is cooling down; refusing solve", "url", url)
		return nil
	}

	for attempt := 0; attempt <= h.cfg.RepairAttempts; attempt++ {
		payload := map[string]any{"cmd": "request.get", "url": url, "maxTimeout": h.cfg.SolveTimeoutMS}
		if h.ensureSession() {
			payload["session"] = h.cfg.Session
		} else if h.cfg.ExitProxy != "" {
			// No session to carry the proxy, so the one-shot browser needs it here.
			payload["proxy"] = map[string]any{"url": h.cfg.ExitProxy}
		}

		answer, err := h.post(payload, h.cfg.HTTPTimeout)
		if err == nil {
			if answer.Solution != nil {
				return answer.Solution
			}
			err = errors.New("FlareSolverr answered without a solution")
		}

		proxyFailure := isProxyConnectionFailure(err)
		_, hadSession := payload["session"]
		if attempt >= h.cfg.RepairAttempts || !hadSession || !proxyFailure {
			if proxyFailure && attempt >= h.cfg.RepairAttempts {
				h.repairBlockedUntil = h.now().Add(h.cfg.RepairCooldown)
			}
			h.log.Warn("FlareSolverr failed", "url", url, "error", err)
			return nil
		}

		h.log.Warn("FlareSolverr session failed; destroying and recreating it so the proxy is rebound",
			"session", h.cfg.Session, "url", url, "proxy", orDirect(h.cfg.ExitProxy), "error", err)
		if err := h.resetSession(); err != nil {
			h.repairBlockedUntil = h.now().Add(h.cfg.RepairCooldown)
			h.log.Warn("FlareSolverr session could not be repaired", "session", h.cfg.Session, "error", err)
			return nil
		}
	}
	return nil
}

func (h *Handler) remember(site string, solution *Solution) {
	c := &Clearance{values: map[string]string{}, UserAgent: solution.UserAgent, earned: h.now()}
	for _, cookie := range solution.Cookies {
		if cookie.Name != "" {
			c.set(cookie.Name, cookie.Value)
		}
	}
	if len(c.names) > 0 && c.UserAgent != "" {
		h.mu.Lock()
		h.clearance[site] = c
		h.mu.Unlock()
	}
}

func (h *Handler) held(site string) *Clearance {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.clearance[site]; ok {
		return c.clone()
	}
	return nil
}

func refetchWith(client *http.Client, url string, held *Clearance, log *slog.Logger) (int, []byte, bool) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, false
	}
	req.Header.Set("User-Agent", held.UserAgent)
	req.Header.Set("Cookie", held.Header())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	// Out through the same exit the clearance was issued to, or Cloudflare
	// hands back another challenge however good the cookie is.
	resp, err := client.Do(req)
	if err != nil {
		log.Warn("re-fetch failed", "url", url, "error", err)
		return 0, nil, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Warn("re-fetch failed", "url", url, "error", err)
		return 0, nil, false
	}
	return resp.StatusCode, body, true
}

// freshClearance is how soon after its solve a refused clearance counts as
// never having worked.
const freshClearance = 5 * time.Minute

// isChallenge tells a Cloudflare challenge page from an origin answer.
func isChallenge(status int, body []byte) bool {
	if status != http.StatusForbidden && status != http.StatusServiceUnavailable {
		return false
	}
	return bytes.Contains(body, []byte("challenge-platform")) || bytes.Contains(body, []byte("<title>Just a moment"))
}

func (h *Handler) forgetClearance() {
	h.mu.Lock()
	clear(h.clearance)
	h.mu.Unlock()
}

// rebuildSession recreates the session at most once per RepairCooldown.
// Called with solveMu held.
func (h *Handler) rebuildSession() {
	if !h.lastRebuild.IsZero() && h.now().Sub(h.lastRebuild) < h.cfg.RepairCooldown {
		return
	}
	h.lastRebuild = h.now()
	if err := h.resetSession(); err != nil {
		// Leave sessionReady false so the next solve tries a one-shot
		// browser, which takes the exit per request.
		h.log.Warn("FlareSolverr session could not be rebuilt", "session", h.cfg.Session, "error", err)
	}
}

func html(req *http.Request, status int, body []byte) *http.Response {
	return httpx.Text(req, status, "text/html; charset=utf-8", body)
}

// serveFromSolver answers a request that has no usable clearance behind it.
//
// Callers arriving together queue on one lock, so an expiry costs a single
// solve however many requests tripped over it. Whoever gets in first pays the
// ~11s; the rest find fresh clearance waiting and re-fetch with it.
//
// suspect says the session has just handed over a clearance the exit refused;
// it is rebuilt before the solve.
func (h *Handler) serveFromSolver(req *http.Request, site string, suspect bool) *http.Response {
	used := strings.Join(req.Header.Values("Cookie"), "; ")
	url := req.URL.String()

	h.solveMu.Lock()
	defer h.solveMu.Unlock()

	if suspect && h.held(site) == nil {
		h.log.Warn("fresh clearance was refused at the exit; rebuilding the session", "site", site, "session", h.cfg.Session)
		h.rebuildSession()
	}

	if held := h.held(site); held != nil && !strings.Contains(used, held.Header()) {
		status, body, ok := h.fetch(url, held)
		switch {
		case ok && !isChallenge(status, body):
			return html(req, status, body)
		case ok:
			// Clearance that is challenged at the exit straight away was not
			// earned there: the session's browser is leaving from somewhere
			// else. Every solve from it would hand over the same useless
			// cookie, so rebuild it before solving.
			h.log.Warn("fresh clearance was challenged at the exit; rebuilding the session", "site", site, "session", h.cfg.Session)
			h.forgetClearance()
			h.rebuildSession()
		}
	}

	solution := h.solve(url)
	if solution == nil {
		return httpx.Text(req, http.StatusBadGateway, "", []byte("FlareSolverr unavailable"))
	}
	h.remember(site, solution)
	status := solution.Status
	if status == 0 {
		status = http.StatusOK
	}
	return html(req, status, []byte(solution.Response))
}

// dress lets the request through to the origin, dressed as the browser that
// solved.
func (h *Handler) dress(req *http.Request, ctx *goproxy.ProxyCtx, held *Clearance) {
	req.Header.Set("User-Agent", held.UserAgent)
	carried := strings.Join(req.Header.Values("Cookie"), "; ")
	if carried != "" {
		req.Header.Set("Cookie", carried+"; "+held.Header())
	} else {
		req.Header.Set("Cookie", held.Header())
	}
	// Cookie and user agent are only two thirds of the disguise; the address
	// has to match too.
	if h.exitRT != nil && ctx != nil {
		ctx.RoundTripper = h.exitRT
	}
}

// Request dresses requests that have clearance and answers the rest itself.
func (h *Handler) Request(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	site := flow.SiteOf(req.URL.Hostname(), h.cfg.Hosts)
	if site == "" {
		return req, nil
	}
	if held := h.held(site); held != nil {
		h.dress(req, ctx, held)
		return req, nil
	}
	return req, h.serveFromSolver(req, site, false)
}

// harvest follows Cloudflare's cookie rotation so the stored clearance stays
// current.
func (h *Handler) harvest(site string, resp *http.Response) {
	h.mu.Lock()
	defer h.mu.Unlock()
	held, ok := h.clearance[site]
	if !ok {
		return
	}
	for _, cookie := range resp.Cookies() {
		if held.values[cookie.Name] != cookie.Value {
			held.set(cookie.Name, cookie.Value)
			h.log.Info("refreshed cookie from Set-Cookie", "cookie", cookie.Name, "site", site)
		}
	}
}

// Response keeps the clearance current and answers a challenged request once
// more from a fresh solve.
func (h *Handler) Response(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	req := resp.Request
	if ctx != nil && ctx.Req != nil {
		req = ctx.Req
	}
	if req == nil {
		return resp
	}
	site := flow.SiteOf(req.URL.Hostname(), h.cfg.Hosts)
	if site == "" {
		return resp
	}

	if resp.Header.Get("cf-mitigated") == "" {
		h.harvest(site, resp)
		return resp
	}

	state := flow.StateOf(ctx)
	if state.Retried {
		h.log.Warn("challenged a freshly solved request; leaving it failed rather than solving in a loop", "url", req.URL.String())
		return resp
	}
	state.Retried = true
	h.mu.Lock()
	held := h.clearance[site]
	delete(h.clearance, site)
	h.mu.Unlock()
	// Cloudflare's clearance lasts far longer than this; one refused within
	// minutes of its solve was never good at the exit.
	suspect := held != nil && h.now().Sub(held.earned) < freshClearance
	h.log.Info("clearance was refused; getting a new one", "site", site, "fresh", suspect)
	_ = resp.Body.Close()
	return h.serveFromSolver(req, site, suspect)
}
