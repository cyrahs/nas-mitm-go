package flaresolverr

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/cyrahs/nas-mitm-go/internal/flow"
)

type post struct {
	payload map[string]any
	timeout time.Duration
}

func newHandler(t *testing.T, fake func(payload map[string]any, calls []post) (*Answer, error)) (*Handler, *[]post) {
	t.Helper()
	cfg := ConfigFromEnv()
	cfg.ExitProxy = "http://home.proxy.svc.cluster.local"
	h, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls := []post{}
	h.post = func(payload map[string]any, timeout time.Duration) (*Answer, error) {
		mu.Lock()
		calls = append(calls, post{payload, timeout})
		snapshot := append([]post(nil), calls...)
		mu.Unlock()
		return fake(payload, snapshot)
	}
	h.sessionReady = true
	h.clearance["javlibrary.com"] = &Clearance{names: []string{"cf_clearance"}, values: map[string]string{"cf_clearance": "old"}, UserAgent: "old-agent"}
	return h, &calls
}

func cmds(calls []post) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.payload["cmd"].(string)
	}
	return out
}

func count(calls []post, cmd string) int {
	n := 0
	for _, c := range calls {
		if c.payload["cmd"] == cmd {
			n++
		}
	}
	return n
}

func TestFailedSessionIsDestroyedRecreatedAndRetriedOnce(t *testing.T) {
	h, calls := newHandler(t, func(payload map[string]any, calls []post) (*Answer, error) {
		switch payload["cmd"] {
		case "request.get":
			if count(calls, "request.get") == 1 {
				return nil, errors.New("proxy connection failed")
			}
			return &Answer{Solution: &Solution{Status: 200, Response: "ok"}}, nil
		case "sessions.list":
			return &Answer{Sessions: []string{}}, nil
		}
		return &Answer{}, nil
	})

	result := h.solve("https://www.javlibrary.com/")
	if result == nil || result.Status != 200 {
		t.Fatalf("got %v", result)
	}
	want := []string{"request.get", "sessions.destroy", "sessions.list", "sessions.create", "request.get"}
	if got := cmds(*calls); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("calls %v, want %v", got, want)
	}
	proxy, _ := (*calls)[3].payload["proxy"].(map[string]any)
	if proxy["url"] != h.cfg.ExitProxy {
		t.Fatalf("session created without the exit proxy: %v", (*calls)[3].payload)
	}
	if len(h.clearance) != 0 {
		t.Fatal("clearance survived the session reset")
	}
}

func TestSecondFailureDoesNotLoopForever(t *testing.T) {
	h, calls := newHandler(t, func(payload map[string]any, _ []post) (*Answer, error) {
		switch payload["cmd"] {
		case "sessions.list":
			return &Answer{Sessions: []string{}}, nil
		case "sessions.create", "sessions.destroy":
			return &Answer{}, nil
		}
		return nil, &HTTPError{Status: 500, Body: `{"message":"Error: net::ERR_PROXY_CONNECTION_FAILED"}`}
	})

	if result := h.solve("https://www.javlibrary.com/"); result != nil {
		t.Fatal("expected no solution")
	}
	if n := count(*calls, "request.get"); n != 2 {
		t.Fatalf("%d request.get, want 2", n)
	}
	if result := h.solve("https://www.javlibrary.com/next"); result != nil {
		t.Fatal("expected no solution while cooling down")
	}
	if n := count(*calls, "sessions.destroy"); n != 1 {
		t.Fatalf("%d sessions.destroy, want 1", n)
	}
}

func TestUnrelatedSolverErrorDoesNotDestroySession(t *testing.T) {
	h, calls := newHandler(t, func(map[string]any, []post) (*Answer, error) {
		return nil, errors.New("target returned malformed response")
	})
	if result := h.solve("https://www.javlibrary.com/"); result != nil {
		t.Fatal("expected no solution")
	}
	if got := cmds(*calls); len(got) != 1 || got[0] != "request.get" {
		t.Fatalf("calls %v", got)
	}
}

func TestControlCallsUseShortTimeout(t *testing.T) {
	h, calls := newHandler(t, func(payload map[string]any, calls []post) (*Answer, error) {
		switch payload["cmd"] {
		case "request.get":
			if count(calls, "request.get") == 1 {
				return nil, errors.New("ERR_PROXY_CONNECTION_FAILED")
			}
			return &Answer{Solution: &Solution{Status: 200}}, nil
		case "sessions.list":
			return &Answer{Sessions: []string{}}, nil
		}
		return &Answer{}, nil
	})
	if result := h.solve("https://www.javlibrary.com/"); result == nil {
		t.Fatal("expected a solution")
	}
	for _, c := range *calls {
		cmd := c.payload["cmd"].(string)
		want := 90 * time.Second
		if strings.HasPrefix(cmd, "sessions.") {
			want = 10 * time.Second
		}
		if c.timeout != want {
			t.Errorf("%s timeout %v, want %v", cmd, c.timeout, want)
		}
	}
}

func solved(h *Handler) {
	h.clearance = map[string]*Clearance{}
}

// A cold fan-out costs one solve: the rest wait on the lock, then re-fetch
// with the clearance it earned.
func TestColdFanOutCostsOneSolve(t *testing.T) {
	var solves int
	var mu sync.Mutex
	h, _ := newHandler(t, func(payload map[string]any, _ []post) (*Answer, error) {
		if payload["cmd"] != "request.get" {
			return &Answer{Sessions: []string{"rsshub"}}, nil
		}
		mu.Lock()
		solves++
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		return &Answer{Solution: &Solution{
			Status: 200, Response: "<html>solved</html>", UserAgent: "Chrome",
			Cookies: []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			}{{"cf_clearance", "fresh"}},
		}}, nil
	})
	solved(h)
	var refetches int
	h.fetch = func(url string, held *Clearance) (int, []byte, bool) {
		mu.Lock()
		refetches++
		mu.Unlock()
		if held.Header() != "cf_clearance=fresh" || held.UserAgent != "Chrome" {
			t.Errorf("re-fetch with %q / %q", held.Header(), held.UserAgent)
		}
		return 200, []byte("<html>refetched</html>"), true
	}

	var wg sync.WaitGroup
	statuses := make([]int, 8)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "https://www.javlibrary.com/cn/?v=x", nil)
			// Before the solve finishes there is no clearance, so every
			// request queues on serveFromSolver.
			_, resp := h.Request(req, &goproxy.ProxyCtx{})
			if resp == nil {
				// Late arrivals find clearance and are dressed instead.
				statuses[i] = -1
				return
			}
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	if solves != 1 {
		t.Fatalf("%d solves, want 1", solves)
	}
	for i, s := range statuses {
		if s != 200 && s != -1 {
			t.Fatalf("request %d got %d", i, s)
		}
	}
}

func TestDressedRequestCarriesClearanceAndExit(t *testing.T) {
	h, _ := newHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "https://www.javlibrary.com/cn/", nil)
	req.Header.Set("Cookie", "over18=18")
	ctx := &goproxy.ProxyCtx{}
	_, resp := h.Request(req, ctx)
	if resp != nil {
		t.Fatal("dressed request was answered locally")
	}
	if req.Header.Get("Cookie") != "over18=18; cf_clearance=old" || req.Header.Get("User-Agent") != "old-agent" {
		t.Fatalf("headers %v", req.Header)
	}
	if ctx.RoundTripper == nil {
		t.Fatal("request not sent through the exit proxy")
	}
}

func TestResponsesAreHarvestedForRotatedClearance(t *testing.T) {
	h, _ := newHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "https://www.javlibrary.com/cn/", nil)
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Set-Cookie": {"cf_clearance=new; Path=/; Secure"}}, Request: req, Body: http.NoBody}
	h.Response(resp, &goproxy.ProxyCtx{Req: req, UserData: &flow.State{}})
	if got := h.clearance["javlibrary.com"].Header(); got != "cf_clearance=new" {
		t.Fatalf("clearance %q", got)
	}
}

func TestChallengedResponseIsSolvedOnceAndNotLooped(t *testing.T) {
	var solves int
	h, _ := newHandler(t, func(payload map[string]any, _ []post) (*Answer, error) {
		if payload["cmd"] == "request.get" {
			solves++
			return &Answer{Solution: &Solution{Status: 200, Response: "<html>ok</html>", UserAgent: "Chrome",
				Cookies: []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				}{{"cf_clearance", "fresh"}}}}, nil
		}
		return &Answer{Sessions: []string{"rsshub"}}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "https://www.javlibrary.com/cn/", nil)
	ctx := &goproxy.ProxyCtx{Req: req, UserData: &flow.State{}}
	h.Request(req, ctx) // dressed with the old clearance
	challenged := func() *http.Response {
		return &http.Response{StatusCode: 403, Header: http.Header{"Cf-Mitigated": {"challenge"}}, Request: req, Body: io.NopCloser(strings.NewReader("challenge"))}
	}
	resp := h.Response(challenged(), ctx)
	if resp.StatusCode != 200 || solves != 1 {
		t.Fatalf("got %d after %d solves", resp.StatusCode, solves)
	}
	again := h.Response(challenged(), ctx)
	if again.StatusCode != 403 || solves != 1 {
		t.Fatalf("retried a retry: %d after %d solves", again.StatusCode, solves)
	}
}
