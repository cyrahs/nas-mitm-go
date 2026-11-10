package suwayomi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type call struct {
	url     string
	header  http.Header
	timeout time.Duration
}

type fakeUpstream struct {
	mu      sync.Mutex
	calls   []call
	detail  func() (*Result, error)
	chapter []func() (*Result, error)
}

func (f *fakeUpstream) fetch(_ context.Context, url string, header http.Header, timeout time.Duration) (*Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{url, header.Clone(), timeout})
	if strings.Contains(url, "/api/v3/comic2/") {
		return f.detail()
	}
	n := 0
	for _, c := range f.calls {
		if !strings.Contains(c.url, "/api/v3/comic2/") {
			n++
		}
	}
	if n > len(f.chapter) {
		return nil, errors.New("unexpected chapter call")
	}
	return f.chapter[n-1]()
}

func (f *fakeUpstream) chapterCalls() []call {
	var out []call
	for _, c := range f.calls {
		if !strings.Contains(c.url, "/api/v3/comic2/") {
			out = append(out, c)
		}
	}
	return out
}

func ok(body string) func() (*Result, error) {
	return func() (*Result, error) {
		return &Result{Status: 200, Header: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"br"}, "Connection": {"keep-alive"}}, Body: []byte(body), Exit: "-"}, nil
	}
}

func throttle() func() (*Result, error) {
	return ok(`{"code":210,"message":"Request was throttled. Expected available in 13 seconds."}`)
}

func fail() func() (*Result, error) {
	return func() (*Result, error) { return nil, errors.New("proxy dial: connection refused") }
}

func detail(freeType int) func() (*Result, error) {
	return func() (*Result, error) {
		body := `{"code":200,"results":{"comic":{"free_type":{"value":` + string(rune('0'+freeType)) + `,"display":"x"}}}}`
		return &Result{Status: 200, Body: []byte(body)}, nil
	}
}

func testConfig() Config {
	return Config{
		UpstreamHost:   "api.manga2026.com",
		ClientDeadline: 30 * time.Second,
		ClientMargin:   3 * time.Second,
		Timeout:        4 * time.Second,
		Retries:        4,
		PaidCapacity:   10,
		PaidWindow:     63 * time.Second,
		PaidFree:       4,
		PaidRampMin:    2 * time.Second,
		PaidRampMax:    12 * time.Second,
	}
}

func newHandler(up *fakeUpstream, clock *fakeClock) *Handler {
	h := New(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.fetch = up.fetch
	if clock != nil {
		h.now = clock.Now
		h.pacer.Now = clock.Now
		h.pacer.Sleep = clock.Sleep
	}
	return h
}

func chapterRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://api.manga2025.com/api/v3/comic/someslug/chapter/0123456789abcdef?platform=3", nil)
	req.Header.Set("Authorization", "Token secret")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "okhttp/4")
	req.Header.Set("Connection", "keep-alive")
	return req
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestFreeChapterGoesOutAnonymouslyToTheFastName(t *testing.T) {
	up := &fakeUpstream{detail: detail(1), chapter: []func() (*Result, error){ok(`{"code":200,"results":{}}`)}}
	h := newHandler(up, nil)

	_, resp := h.Request(chapterRequest(), nil)
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("got %v", resp)
	}
	if body := readAll(t, resp); body != `{"code":200,"results":{}}` {
		t.Fatalf("body %q", body)
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Connection") != "" {
		t.Fatalf("hop-by-hop headers passed back: %v", resp.Header)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("content type lost: %v", resp.Header)
	}

	calls := up.chapterCalls()
	if len(calls) != 1 {
		t.Fatalf("%d chapter calls", len(calls))
	}
	c := calls[0]
	if c.url != "https://api.manga2026.com/api/v3/comic/someslug/chapter/0123456789abcdef?platform=3" {
		t.Fatalf("url %s", c.url)
	}
	if c.header.Get("Authorization") != "" {
		t.Fatal("free chapter still carries the credential")
	}
	if c.header.Get("Accept-Encoding") != "br" || c.header.Get("User-Agent") != "okhttp/4" || c.header.Get("Connection") != "" {
		t.Fatalf("headers %v", c.header)
	}
	if up.calls[0].url != "https://api.manga2026.com/api/v3/comic2/someslug?platform=3" || up.calls[0].header.Get("source") != "copyApp" {
		t.Fatalf("detail lookup %v", up.calls[0])
	}
}

func TestPaidChapterKeepsTheCredentialAndFreeTypeIsCached(t *testing.T) {
	up := &fakeUpstream{detail: detail(2), chapter: []func() (*Result, error){ok(`{}`), ok(`{}`)}}
	h := newHandler(up, &fakeClock{t: time.Unix(1_700_000_000, 0)})

	h.Request(chapterRequest(), nil)
	h.Request(chapterRequest(), nil)

	lookups := len(up.calls) - len(up.chapterCalls())
	if lookups != 1 {
		t.Fatalf("%d free_type lookups, want 1", lookups)
	}
	for _, c := range up.chapterCalls() {
		if c.header.Get("Authorization") != "Token secret" {
			t.Fatal("paid chapter lost its credential")
		}
	}
}

func TestFailedFreeTypeLookupMeansPaid(t *testing.T) {
	up := &fakeUpstream{
		detail:  func() (*Result, error) { return &Result{Status: 403, Body: []byte("error code: 1010")}, nil },
		chapter: []func() (*Result, error){ok(`{}`)},
	}
	h := newHandler(up, nil)
	h.Request(chapterRequest(), nil)
	if up.chapterCalls()[0].header.Get("Authorization") == "" {
		t.Fatal("credential stripped although the title could not be classified")
	}
}

func TestThrottleIsRetriedThenPassedThrough(t *testing.T) {
	up := &fakeUpstream{detail: detail(1), chapter: []func() (*Result, error){throttle(), fail(), ok(`{"code":200}`)}}
	h := newHandler(up, nil)
	_, resp := h.Request(chapterRequest(), nil)
	if resp.StatusCode != 200 || readAll(t, resp) != `{"code":200}` {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if n := len(up.chapterCalls()); n != 3 {
		t.Fatalf("%d attempts, want 3", n)
	}
}

func TestExhaustedThrottleIsNeverHandedBack(t *testing.T) {
	up := &fakeUpstream{detail: detail(1), chapter: []func() (*Result, error){throttle(), throttle(), throttle(), throttle()}}
	h := newHandler(up, nil)
	_, resp := h.Request(chapterRequest(), nil)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "30" {
		t.Fatalf("got %d %v", resp.StatusCode, resp.Header)
	}
	if body := readAll(t, resp); strings.Contains(body, "210") {
		t.Fatalf("throttle body leaked: %s", body)
	}
}

func TestUnreachableUpstreamIs502(t *testing.T) {
	up := &fakeUpstream{detail: detail(1), chapter: []func() (*Result, error){fail(), fail(), fail(), fail()}}
	h := newHandler(up, nil)
	_, resp := h.Request(chapterRequest(), nil)
	if resp.StatusCode != 502 {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

// A paid chapter that spent its budget waiting for the pacer answers 504
// instead of succeeding into a connection nobody is listening to.
func TestBudgetExhaustionIs504(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	up := &fakeUpstream{detail: detail(2)}
	slow := func() (*Result, error) { clock.Advance(14 * time.Second); return nil, errors.New("timeout") }
	up.chapter = []func() (*Result, error){slow, slow, slow, slow}
	h := newHandler(up, clock)
	_, resp := h.Request(chapterRequest(), nil)
	if resp.StatusCode != 504 {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if n := len(up.chapterCalls()); n != 2 {
		t.Fatalf("%d attempts, want 2", n)
	}
}

func TestAttemptTimeoutSharesTheBudget(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	h := newHandler(&fakeUpstream{}, clock)
	started := clock.Now()
	if got := h.attemptTimeout(started, 1); got != 4*time.Second {
		t.Fatalf("fresh budget %v, want 4s", got)
	}
	clock.Advance(21 * time.Second) // a capped pacing wait
	if got := h.attemptTimeout(started, 1); got != 1500*time.Millisecond {
		t.Fatalf("after pacing %v, want 1.5s", got)
	}
	clock.Advance(6 * time.Second)
	if got := h.attemptTimeout(started, 2); got != 0 {
		t.Fatalf("spent budget %v, want 0", got)
	}
}

func TestBrowsingIsLeftAlone(t *testing.T) {
	up := &fakeUpstream{}
	h := newHandler(up, nil)
	req := httptest.NewRequest(http.MethodGet, "https://api.manga2025.com/api/v3/comic2/someslug?platform=3", nil)
	if _, resp := h.Request(req, nil); resp != nil {
		t.Fatal("non-chapter request was answered")
	}
	if len(up.calls) != 0 {
		t.Fatal("non-chapter request reached the fetcher")
	}
}

func TestThrottleDetection(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   bool
	}{
		{200, `{"code":210,"message":"x"}`, true},
		{200, `{"code": 210}`, true},
		{210, ``, true},
		{200, `{"code":200}`, false},
	}
	for _, c := range cases {
		if got := throttled(c.status, []byte(c.body)); got != c.want {
			t.Errorf("throttled(%d, %s) = %v", c.status, c.body, got)
		}
	}
	if got := throttleWait([]byte(`{"message":"Expected available in 13 seconds."}`)); got != "13" {
		t.Errorf("throttleWait = %s", got)
	}
}

func TestIdentityHashesTheToken(t *testing.T) {
	if identity(http.Header{}) != "anon" {
		t.Fatal("no token should be anon")
	}
	got := identity(http.Header{"Authorization": {"Token secret"}})
	if len(got) != 8 || strings.Contains(got, "secret") {
		t.Fatalf("identity %q", got)
	}
}
