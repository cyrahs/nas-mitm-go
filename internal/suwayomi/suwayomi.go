// Package suwayomi routes each chapter read by what the upstream actually
// counts.
//
// The upstream runs two Django REST Framework throttles side by side, and
// which one applies depends on whether the request carries a credential.
// Measured 2026-08 from inside the Pod, both trip on the 11th request per
// minute:
//
//	credentialled   keyed on the ACCOUNT   rotation is useless
//	anonymous       keyed on the EXIT IP   rotation defeats it entirely
//
// That asymmetry is the whole design. A rotating residential exit gives every
// request a fresh address, which empties a fresh anonymous bucket every time
// but does nothing at all for the account bucket -- a 132-chapter run
// produced 178 distinct exit addresses and still collected 53 rejections,
// with the advertised recovery counting down 13/11/7/3 across four retries of
// one chapter, proving all four drew on one bucket.
//
// So the credential is only worth sending when it buys something. It does for
// paid titles: a mid-series chapter returns 37 pages with the token and 5
// without. It buys nothing for free titles, verified page-for-page (56/56,
// 164/164, 38/38, and mid-series 4/4, 9/9, 28/28). Free chapters therefore go
// out anonymously and ride the rotation; paid chapters keep the token and are
// paced under the account limit instead.
//
// Sampling matters when checking this: the opening chapters of a paid title
// are free preview and return identically either way, so only a mid-series
// chapter can tell the two apart.
//
// Note the throttle arrives as HTTP 200 with code 210 in the body, and the
// extension renders that into a one-page PNG which Suwayomi stores as a
// completed chapter. A throttle that reaches the client is therefore not a
// visible failure but a silently corrupted download, which is why exhausting
// retries returns 503 here rather than passing the body back.
//
// This is a port of the mitmproxy addon that lived in nas-gitops
// (apps/suwayomi/mitm/addon.py); the measurements above were made with it.
package suwayomi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/cyrahs/nas-mitm-go/internal/env"
	"github.com/cyrahs/nas-mitm-go/internal/httpx"
)

// The two hot-manga API hosts. One backend behind two names -- chapter UUIDs
// resolve to the same chapter on either, verified by page count and page
// URLs -- and they share one throttle bucket, so alternating between them
// buys no extra quota.
//
// They are not equally fast, though. 2026 sits behind Cloudflare while 2025
// points at the origin directly, and with US-pinned exits the edge wins at
// every percentile: p50 1.94s against 2.52s, p90 2.39s against 3.26s. That
// margin is what UpstreamHost exists to capture.
var apiHosts = []string{"manga2025.com", "manga2026.com"}

// Only the chapter-contents endpoint is throttled. Search, listings, comic
// detail and chapter *lists* all ran 20/20 clean and none of them drain the
// chapter bucket, so they are left alone entirely.
var chapterPath = regexp.MustCompile(`^/api/v\d+/comic/([^/]+)/chapter/`)

// Never forwarded upstream: these describe the client's hop, not the request.
var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"proxy-connection":    true,
	"te":                  true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
	// Ours to set from what the upstream actually returns.
	"content-length":   true,
	"content-encoding": true,
}

// Cloudflare rejects requests that do not look like a browser with 403
// "error code: 1010", its browser-integrity check. Chapter reads carry the
// extension's own headers and pass; the free_type lookup builds its own
// request and needs a plausible identity of its own, or every title is
// misread as paid -- which strips nothing, but paces everything.
var detailHeaders = map[string]string{
	"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
	"Accept":          "application/json, text/plain, */*",
	"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
	"platform":        "3",
	"source":          "copyApp",
}

// Config holds the tunables, all read from the environment so they can be
// adjusted in nas-gitops without a rebuild.
type Config struct {
	// Where chapter reads are actually sent, regardless of which name the
	// client used. Measured 2026-08 through us.decodo.com over 25
	// interleaved rounds:
	//
	//	         p50     p75     p90     p95     max
	//	2025    2.52s   2.89s   3.26s   3.33s   3.44s
	//	2026    1.94s   2.13s   2.39s   2.91s   3.36s
	//
	// The rewrite lives here rather than in the extension's api_domain
	// setting because that option selects a whole strategy -- API routes and
	// which credential is attached -- not just a base URL, and picking it
	// breaks chapter reads outright.
	UpstreamHost string
	// The rotating residential exit (an HTTP proxy).
	Decodo string
	// Everything happens inside one client request, and Suwayomi's OkHttp
	// abandons it after 30s -- at which point the extension renders a
	// "timeout" image that Suwayomi files as a finished chapter. So the
	// deadline is the client's, not the origin's, and it covers pacing and
	// retries together. A few seconds are held back so the response has time
	// to reach the client after the last attempt returns.
	ClientDeadline time.Duration
	ClientMargin   time.Duration
	// Ceiling for one upstream attempt. Sampled over 60 sequential chapter
	// reads: p50 1.92s, p90 2.90s, p95 3.26s, p99 5.44s. Cutting at 4s clears
	// p95 with room and gives up on the tail deliberately -- a retry draws a
	// new exit and usually returns in under two seconds.
	Timeout time.Duration
	// Retries only help the anonymous arm, where each attempt draws a new
	// address and therefore a new bucket. On the paid arm the pacer is what
	// protects the account bucket.
	Retries int
	// Measured ceiling is 10 requests per 60s sliding window, keyed on the
	// account. See Pacer.
	PaidCapacity int
	PaidWindow   time.Duration
	PaidFree     int
	PaidRampMin  time.Duration
	PaidRampMax  time.Duration

	LogExitIP bool
	ExitEcho  string
}

// ConfigFromEnv reads the same variables the mitmproxy addon did.
func ConfigFromEnv() Config {
	return Config{
		UpstreamHost:   env.String("UPSTREAM_HOST", "api.manga2026.com"),
		Decodo:         env.String("DECODO", "http://gate.decodo.com:10000"),
		ClientDeadline: env.Seconds("CLIENT_DEADLINE", 30),
		ClientMargin:   env.Seconds("CLIENT_MARGIN", 3),
		Timeout:        env.Seconds("UPSTREAM_TIMEOUT", 4),
		Retries:        env.Int("RETRIES", 4),
		PaidCapacity:   env.Int("PAID_CAPACITY", 10),
		PaidWindow:     env.Seconds("PAID_WINDOW", 63),
		PaidFree:       env.Int("PAID_FREE_SLOTS", 4),
		PaidRampMin:    env.Seconds("PAID_RAMP_MIN", 2),
		PaidRampMax:    env.Seconds("PAID_RAMP_MAX", 12),
		LogExitIP:      env.Bool("LOG_EXIT_IP"),
		ExitEcho:       env.String("EXIT_ECHO", "https://api.ipify.org"),
	}
}

// Result is one upstream attempt.
type Result struct {
	Status int
	Header http.Header
	Body   []byte
	Exit   string
}

// FetchFunc makes one upstream attempt on a connection of its own.
type FetchFunc func(ctx context.Context, url string, header http.Header, timeout time.Duration) (*Result, error)

// Handler is the suwayomi chapter router.
type Handler struct {
	cfg   Config
	log   *slog.Logger
	pacer *Pacer
	fetch FetchFunc
	now   func() time.Time

	// free_type comes from the comic-detail endpoint, which is not
	// throttled, and a title does not change from free to paid
	// mid-download -- so it is looked up once per comic and kept.
	freeMu    sync.Mutex
	freeCache map[string]bool
}

// New returns a handler that fetches through cfg.Decodo.
func New(cfg Config, logger *slog.Logger) *Handler {
	h := &Handler{
		cfg:       cfg,
		log:       logger.With("handler", "suwayomi"),
		now:       time.Now,
		freeCache: map[string]bool{},
	}
	h.pacer = &Pacer{
		Capacity: cfg.PaidCapacity,
		Window:   cfg.PaidWindow,
		Free:     cfg.PaidFree,
		RampMin:  cfg.PaidRampMin,
		RampMax:  cfg.PaidRampMax,
		Now:      time.Now,
		Sleep:    time.Sleep,
	}
	h.fetch = h.fetchDecodo
	h.log.Info("handler ready: free titles anonymous, paid paced",
		"capacity", cfg.PaidCapacity, "window", cfg.PaidWindow,
		"free_slots", cfg.PaidFree, "ramp_min", cfg.PaidRampMin, "ramp_max", cfg.PaidRampMax)
	return h
}

func (h *Handler) Name() string    { return "suwayomi" }
func (h *Handler) Hosts() []string { return apiHosts }

func (h *Handler) Response(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response { return resp }

// fetchDecodo builds a transport per attempt and closes it afterwards: a
// pooled connection would put this request back on the previous exit address
// -- the precise thing this handler exists to avoid.
func (h *Handler) fetchDecodo(ctx context.Context, url string, header http.Header, timeout time.Duration) (*Result, error) {
	transport, err := httpx.Transport(h.cfg.Decodo, false)
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}

	exit := "-"
	if h.cfg.LogExitIP {
		exit = exitAddress(ctx, client, h.cfg.ExitEcho)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = header.Clone()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := raw
	// Asking for an encoding by hand turns off Go's own decompression, so
	// the body arrives as the origin sent it. Content-Encoding is not passed
	// on (it is hop-by-hop here), so the body must be decoded or the client
	// sees a plausible 200 whose JSON starts 1f 8b.
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" {
		decoded, err := httpx.Decode(raw, encoding)
		if err != nil {
			h.log.Warn("could not decode body", "encoding", encoding, "error", err)
		}
		body = decoded
	}
	return &Result{Status: resp.StatusCode, Header: resp.Header, Body: body, Exit: exit}, nil
}

// exitAddress asks the echo service which address the client leaves from.
func exitAddress(ctx context.Context, client *http.Client, echo string) string {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, echo, nil)
	if err != nil {
		return "?"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "?"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(body))
}

// throttled: the throttle arrives as HTTP 200 with the real code in the JSON
// body. Checking the status alone scores a throttled response as a success,
// which is how a batch download ends up storing error pages as chapters.
func throttled(status int, body []byte) bool {
	if status == 210 {
		return true
	}
	s := string(body)
	return strings.Contains(s, `"code":210`) || strings.Contains(s, `"code": 210`)
}

var throttleWaitPattern = regexp.MustCompile(`in (\d+) second`)

// throttleWait pulls the advertised recovery out of the throttle body.
func throttleWait(body []byte) string {
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "?"
	}
	if m := throttleWaitPattern.FindStringSubmatch(payload.Message); m != nil {
		return m[1]
	}
	return "?"
}

// identity hashes the credential so runs can be correlated without logging it.
func identity(header http.Header) string {
	token := header.Get("Authorization")
	if token == "" {
		return "anon"
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:8]
}

// isFree reports whether a title costs nothing: free_type.value is 1 free, 2
// paid. On any error the answer is false -- the safe direction, since
// treating a paid title as free would strip the credential and silently
// truncate every chapter to a 5-page preview, which Suwayomi would store as a
// complete download.
func (h *Handler) isFree(ctx context.Context, host, slug string) bool {
	h.freeMu.Lock()
	if free, ok := h.freeCache[slug]; ok {
		h.freeMu.Unlock()
		return free
	}
	h.freeMu.Unlock()

	free := false
	target := h.cfg.UpstreamHost
	if target == "" {
		target = host
	}
	header := http.Header{}
	for k, v := range detailHeaders {
		header.Set(k, v)
	}
	result, err := h.fetch(ctx, fmt.Sprintf("https://%s/api/v3/comic2/%s?platform=3", target, slug), header, h.cfg.Timeout)
	switch {
	case err != nil:
		h.log.Warn("free_type lookup failed, treating as paid", "comic", slug, "error", err)
	case result.Status != http.StatusOK:
		// Worth its own line: a non-200 here is not a missing title, it is
		// usually the edge refusing the request shape, and the fallback to
		// "paid" would otherwise hide that behind unnecessary pacing.
		h.log.Warn("free_type lookup refused, treating as paid", "comic", slug, "status", result.Status)
	default:
		var payload struct {
			Code    int `json:"code"`
			Results struct {
				Comic struct {
					FreeType struct {
						Value   int    `json:"value"`
						Display string `json:"display"`
					} `json:"free_type"`
				} `json:"comic"`
			} `json:"results"`
		}
		if err := json.Unmarshal(result.Body, &payload); err != nil {
			h.log.Warn("free_type lookup unreadable, treating as paid", "comic", slug, "error", err)
		} else if payload.Code == 200 {
			ft := payload.Results.Comic.FreeType
			free = ft.Value == 1
			arm := "PAID (credentialled, paced)"
			if free {
				arm = "FREE (anonymous, rotating exit)"
			}
			h.log.Info("free_type", "comic", slug, "free_type", ft.Display, "arm", arm)
		}
	}

	h.freeMu.Lock()
	h.freeCache[slug] = free
	h.freeMu.Unlock()
	return free
}

// attemptTimeout is how long this attempt may take without overrunning the
// client.
//
// The budget is shared: whatever the pacer already slept comes out of it, and
// what remains is divided among the attempts still to come. Without this the
// two costs add up independently -- a capped 21s pacing wait plus a 10s
// attempt is 31s, one second past the point where the extension has already
// given up and written an error page.
//
// It returns 0 when nothing useful is left, which the caller treats as a
// reason to stop rather than to try one more time and answer into the void.
func (h *Handler) attemptTimeout(started time.Time, attempt int) time.Duration {
	spent := h.now().Sub(started)
	remaining := h.cfg.ClientDeadline - h.cfg.ClientMargin - spent
	if remaining <= 0 {
		return 0
	}
	left := h.cfg.Retries - attempt + 1
	if left < 1 {
		left = 1
	}
	budget := remaining / time.Duration(left)
	if budget > h.cfg.Timeout {
		budget = h.cfg.Timeout
	}
	if budget < time.Second {
		budget = time.Second
	}
	return budget
}

func jsonResponse(req *http.Request, status int, body string, extra map[string]string) *http.Response {
	header := http.Header{"Content-Type": {"application/json"}}
	for k, v := range extra {
		header.Set(k, v)
	}
	return httpx.NewResponse(req, status, header, []byte(body))
}

// Request answers chapter reads itself and lets everything else through.
func (h *Handler) Request(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	match := chapterPath.FindStringSubmatch(req.URL.Path)
	if match == nil {
		// Browsing traffic is not throttled and does not feed the chapter
		// bucket, so routing it through Decodo would add ~1.2s per call to
		// buy nothing.
		return req, nil
	}
	slug := match[1]
	host := req.URL.Hostname()
	ctx := req.Context()

	header := http.Header{}
	for name, values := range req.Header {
		if hopByHop[strings.ToLower(name)] || strings.EqualFold(name, "host") {
			continue
		}
		header[name] = append([]string(nil), values...)
	}

	// Started before pacing, not after: the client's clock is already running
	// while the pacer sleeps, so a wait that is not counted is a wait that
	// silently eats the retry budget.
	started := h.now()

	free := h.isFree(ctx, host, slug)
	var waited time.Duration
	if free {
		// Anonymous requests are counted per exit address, and every attempt
		// here leaves from a new one -- so dropping the credential moves this
		// request into a bucket the rotation refills for free. Verified to
		// return byte-identical page counts for free titles.
		header.Del("Authorization")
	} else {
		// The credential is required (without it a paid chapter truncates to
		// 5 pages) and it binds this request to the account bucket, which no
		// amount of rotation can enlarge. Pacing is the only remedy.
		waited = h.pacer.Wait()
	}

	// Cloudflare serves brotli only when it is asked for alone -- listing gzip
	// alongside gets gzip back. The client's own header is replaced rather
	// than forwarded, which is safe because the body is decompressed here
	// regardless and reaches the client as plain JSON.
	header.Set("Accept-Encoding", "br")

	// Send the read to whichever name is faster, whatever the client asked
	// for. Only the host is substituted -- path, query and UUID are
	// untouched, and a UUID addresses the same chapter on either name.
	target := host
	if h.cfg.UpstreamHost != "" {
		target = h.cfg.UpstreamHost
	}
	url := "https://" + target + req.URL.RequestURI()

	arm := "paid"
	if free {
		arm = "free"
	}
	ident := identity(header)
	chapter := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
	if len(chapter) > 8 {
		chapter = chapter[:8]
	}
	log := h.log.With("chapter", chapter, "arm", arm, "ident", ident)

	var result *Result
	for attempt := 1; attempt <= h.cfg.Retries; attempt++ {
		budget := h.attemptTimeout(started, attempt)
		if budget <= 0 {
			// Out of time. Answering now with an error is the honest move --
			// a late success would arrive after the extension has already
			// rendered its timeout page and Suwayomi has filed the chapter.
			log.Error("BUDGET EXHAUSTED", "attempts", attempt-1, "elapsed", h.now().Sub(started).Round(10*time.Millisecond))
			return req, jsonResponse(req, http.StatusGatewayTimeout, `{"code":504,"message":"client deadline reached"}`, nil)
		}

		res, err := h.fetch(ctx, url, header, budget)
		if err != nil {
			log.Warn("attempt failed", "attempt", attempt, "of", h.cfg.Retries, "budget", budget, "error", err)
			if attempt == h.cfg.Retries {
				return req, httpx.Text(req, http.StatusBadGateway, "", []byte("upstream unreachable"))
			}
			continue
		}
		result = res

		if !throttled(res.Status, res.Body) {
			args := []any{"attempt", attempt, "exit", res.Exit, "elapsed", h.now().Sub(started).Round(10 * time.Millisecond)}
			if waited > 0 {
				args = append(args, "paced", waited.Round(100*time.Millisecond))
			}
			log.Info("ok", args...)
			break
		}

		log.Warn("THROTTLED", "attempt", attempt, "exit", res.Exit, "wait_s", throttleWait(res.Body))

		if attempt == h.cfg.Retries {
			// Never hand a 210 back: the extension renders it into a one-page
			// image and Suwayomi files that as a completed chapter. A 503 is
			// recorded as a failure instead, which is recoverable.
			log.Error("EXHAUSTED", "attempts", h.cfg.Retries, "elapsed", h.now().Sub(started).Round(10*time.Millisecond))
			return req, jsonResponse(req, http.StatusServiceUnavailable,
				`{"code":503,"message":"upstream throttled, retries exhausted"}`,
				map[string]string{"Retry-After": "30"})
		}
	}
	if result == nil {
		return req, httpx.Text(req, http.StatusBadGateway, "", nil)
	}

	out := http.Header{}
	for name, values := range result.Header {
		if hopByHop[strings.ToLower(name)] {
			continue
		}
		out[name] = append([]string(nil), values...)
	}
	return req, httpx.NewResponse(req, result.Status, out, result.Body)
}
