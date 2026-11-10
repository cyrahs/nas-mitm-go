// Package bilibili carries the browser's live bilibili cookies into RSSHub's
// requests.
//
// bilibili answers RSSHub with `-352 风控校验失败`, and the usual remedies do
// not touch it. Measured from the Pod against /x/space/wbi/arc/search, with a
// correct WBI signature every time:
//
//	datacentre egress, no cookie                -352
//	datacentre egress, freshly issued buvid3    -352
//	residential egress, no cookie               -352
//	residential egress, freshly issued buvid3   -352
//	datacentre egress, browser's cookies        code 0
//	residential egress, browser's cookies       code 0
//
// So the exit address is not what is being scored, and a buvid3 picked up
// from the homepage is not enough either. What clears the check is the set a
// real browser accumulated -- bili_ticket, a buvid3/4 pair that went through
// bilibili's fingerprint registration, and the logged-in half. Dropping just
// the account cookies from an otherwise complete set puts it back to -352, so
// the session is doing real work here; this cannot be an anonymous fetch.
//
// That set cannot live in RSSHub's env: bilibili rotates SESSDATA and expires
// bili_ticket every few days, and a value pasted into a Secret is stale by
// the next rotation. So the cookies are pulled on a timer and written onto
// each request on its way out.
//
// They come from fav (GET /api/v2/credentials/bilibili-main), which holds the
// login captured on its 登录态 page and keeps it alive itself. fav is the one
// writer of that session; nothing here may refresh it, because a refresh
// retires the pair fav holds.
//
// The Cookie header is replaced outright rather than merged. RSSHub mints its
// own anonymous buvid before calling, and serving both its values and the
// browser's means duplicate names and a session that half-matches -- which is
// the shape risk control is looking for.
//
// Responses are not harvested for Set-Cookie. The source is the authority; a
// value picked up here would drift from its copy and be overwritten at the
// next poll anyway.
//
// Both exits pass, so requests go out the Pod's own address. Set
// BILI_EXIT_PROXY to an HTTP proxy if bilibili ever starts scoring this
// cluster's addresses; empty means direct.
//
// This is a port of the mitmproxy addon that lived in nas-gitops
// (apps/rss/rsshub/mitmproxy/bilibili.py).
package bilibili

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/cyrahs/nas-mitm-go/internal/env"
	"github.com/cyrahs/nas-mitm-go/internal/flow"
	"github.com/cyrahs/nas-mitm-go/internal/httpx"
)

var syncedHosts = []string{"bilibili.com"}

// Config holds the tunables.
type Config struct {
	FavURL    string
	FavToken  string
	ExitProxy string
	// fav renews bili_ticket days ahead and SESSDATA only when bilibili asks,
	// so a few minutes behind it is plenty; a rejected request asks sooner.
	PollInterval time.Duration
	// Floor between syncs so a run of rejected requests cannot turn into a
	// stream of fetches from fav.
	MinRefresh  time.Duration
	HTTPTimeout time.Duration
}

// ConfigFromEnv reads the deployment's settings.
func ConfigFromEnv() Config {
	return Config{
		FavURL:       env.String("FAV_CREDENTIAL_URL", ""),
		FavToken:     env.String("FAV_CREDENTIAL_TOKEN", ""),
		ExitProxy:    env.String("BILI_EXIT_PROXY", ""),
		PollInterval: 300 * time.Second,
		MinRefresh:   60 * time.Second,
		HTTPTimeout:  20 * time.Second,
	}
}

// FavCookie is one cookie of fav's session.
type FavCookie struct {
	Name    string   `json:"name"`
	Value   string   `json:"value"`
	Domain  string   `json:"domain"`
	Expires *float64 `json:"expires"`
}

// FavAnswer is fav's credential response.
type FavAnswer struct {
	Status  string      `json:"status"`
	Cookies []FavCookie `json:"cookies"`
}

type cookie struct{ name, value string }

// Handler injects the cookies.
type Handler struct {
	cfg      Config
	log      *slog.Logger
	fetchFav func() (*FavAnswer, error)
	exitRT   goproxy.RoundTripper
	now      func() time.Time

	mu  sync.RWMutex
	jar []cookie

	refresh chan struct{}
}

// New returns the handler; call Start to begin polling.
func New(cfg Config, logger *slog.Logger) (*Handler, error) {
	h := &Handler{
		cfg:     cfg,
		log:     logger.With("handler", "bilibili"),
		now:     time.Now,
		refresh: make(chan struct{}, 1),
	}
	direct, err := httpx.Transport("", true)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: direct, Timeout: cfg.HTTPTimeout}
	h.fetchFav = func() (*FavAnswer, error) { return fetchFav(client, cfg.FavURL, cfg.FavToken) }
	if cfg.ExitProxy != "" {
		exit, err := httpx.Transport(cfg.ExitProxy, true)
		if err != nil {
			return nil, err
		}
		h.exitRT = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			return exit.RoundTrip(req)
		})
	}
	return h, nil
}

func (h *Handler) Name() string    { return "bilibili" }
func (h *Handler) Hosts() []string { return syncedHosts }

func (h *Handler) configured() bool { return h.cfg.FavURL != "" && h.cfg.FavToken != "" }

// fetchFav reads the session fav holds: directly, inside the cluster, with
// this client's own token.
func fetchFav(client *http.Client, url, token string) (*FavAnswer, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fav answered HTTP %d", resp.StatusCode)
	}
	var answer FavAnswer
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, err
	}
	return &answer, nil
}

// collect keeps every unexpired cookie of fav's session that belongs to a
// synced host. A name seen twice keeps its first position and its last value.
func (h *Handler) collect(answer *FavAnswer) []cookie {
	var jar []cookie
	index := map[string]int{}
	now := float64(h.now().UnixNano()) / 1e9
	for _, c := range answer.Cookies {
		domain := strings.TrimLeft(c.Domain, ".")
		if c.Name == "" || flow.SiteOf(domain, syncedHosts) == "" {
			continue
		}
		if c.Expires != nil && *c.Expires != 0 && *c.Expires < now {
			continue
		}
		if i, ok := index[c.Name]; ok {
			jar[i].value = c.Value
			continue
		}
		index[c.Name] = len(jar)
		jar = append(jar, cookie{c.Name, c.Value})
	}
	return jar
}

// sync returns the jar fav holds, or nothing when fav says its session is not
// a login. An unreachable fav is an error, so the caller keeps its jar.
func (h *Handler) sync() ([]cookie, error) {
	answer, err := h.fetchFav()
	if err != nil {
		return nil, err
	}
	jar := h.collect(answer)
	if len(jar) > 0 && answer.Status != "invalid" {
		return jar, nil
	}
	status := answer.Status
	if status == "" {
		status = "unknown"
	}
	h.log.Warn("fav's bilibili session is not usable", "status", status, "cookies", len(jar))
	return nil, nil
}

func names(jar []cookie) []string {
	out := make([]string, len(jar))
	for i, c := range jar {
		out[i] = c.name
	}
	return out
}

// Start polls fav until ctx ends: on a timer, and sooner when a response says
// the jar is not working. A failed sync keeps the previous jar rather than
// clearing it: an unreachable source is no reason to drop back to requests
// that are known to be refused.
func (h *Handler) Start(ctx context.Context) {
	if !h.configured() {
		h.log.Error("FAV_CREDENTIAL_URL and FAV_CREDENTIAL_TOKEN are not both set; bilibili requests will go out with whatever RSSHub generated")
		return
	}
	go func() {
		for {
			jar, err := h.sync()
			switch {
			case err != nil:
				h.log.Warn("cookie sync failed, keeping what is in hand", "error", err)
			case len(jar) > 0:
				h.mu.Lock()
				h.jar = jar
				h.mu.Unlock()
				h.log.Info("cookies synced from fav", "names", names(jar))
			default:
				h.mu.RLock()
				held := len(h.jar)
				h.mu.RUnlock()
				h.log.Warn("fav gave no usable cookies; keeping the ones in hand", "held", held)
			}
			last := h.now()
			select {
			case <-h.refresh:
			default:
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(h.cfg.PollInterval):
				continue
			case <-h.refresh:
			}
			if waited := h.now().Sub(last); waited < h.cfg.MinRefresh {
				select {
				case <-ctx.Done():
					return
				case <-time.After(h.cfg.MinRefresh - waited):
				}
			}
		}
	}()
}

func header(jar []cookie) string {
	parts := make([]string, len(jar))
	for i, c := range jar {
		parts[i] = c.name + "=" + c.value
	}
	return strings.Join(parts, "; ")
}

// Request replaces the Cookie header with fav's jar.
func (h *Handler) Request(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if flow.SiteOf(req.URL.Hostname(), syncedHosts) == "" {
		return req, nil
	}
	if h.exitRT != nil && ctx != nil {
		ctx.RoundTripper = h.exitRT
	}
	h.mu.RLock()
	jar := h.jar
	h.mu.RUnlock()
	if len(jar) == 0 {
		// Nothing to inject yet. Letting it through anonymously will almost
		// certainly earn a -352, but failing it here would look identical to
		// RSSHub and hide the reason.
		h.log.Warn("no cookies in hand; letting the request through unchanged", "url", req.URL.String())
		return req, nil
	}
	req.Header.Set("Cookie", header(jar))
	return req, nil
}

// riskControlled: risk control, or a session that is no longer a login. -101
// is what a request still carrying a SESSDATA fav has just refreshed away
// gets; the next sync picks up the new pair.
func riskControlled(resp *http.Response) bool {
	if resp.StatusCode == http.StatusPreconditionFailed {
		return true
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		return false
	}
	body, err := httpx.ReadBody(resp)
	if err != nil {
		return false
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" {
		if decoded, err := httpx.Decode(body, encoding); err == nil {
			body = decoded
		}
	}
	return bytes.Contains(body, []byte(`"code":-352`)) || bytes.Contains(body, []byte(`"code":-101`))
}

// Response asks for a newer jar when bilibili refuses the one in hand.
func (h *Handler) Response(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	req := resp.Request
	if ctx != nil && ctx.Req != nil {
		req = ctx.Req
	}
	if req == nil || flow.SiteOf(req.URL.Hostname(), syncedHosts) == "" {
		return resp
	}
	if !riskControlled(resp) {
		return resp
	}
	h.mu.RLock()
	held := names(h.jar)
	h.mu.RUnlock()
	// Names only: enough to tell a jar missing bili_ticket from one that lost
	// the account half, without putting the session in the log.
	h.log.Warn("bilibili refused the cookies in hand; asking for a newer set", "url", req.URL.String(), "names", held)
	select {
	case h.refresh <- struct{}{}:
	default:
	}
	return resp
}
