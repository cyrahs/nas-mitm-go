package bilibili

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ptr(f float64) *float64 { return &f }

func favAnswer(status string) *FavAnswer {
	now := float64(time.Now().Unix())
	return &FavAnswer{Status: status, Cookies: []FavCookie{
		{Name: "SESSDATA", Value: "s", Domain: ".bilibili.com", Expires: ptr(now + 86400)},
		{Name: "bili_ticket", Value: "t", Domain: ".bilibili.com"},
		{Name: "old", Value: "x", Domain: ".bilibili.com", Expires: ptr(1)},
		{Name: "other", Value: "y", Domain: ".example.com"},
	}}
}

func newHandler(t *testing.T) *Handler {
	t.Helper()
	h, err := New(Config{
		FavURL:   "http://fav.media.svc.cluster.local/api/v2/credentials/bilibili-main",
		FavToken: "token", PollInterval: time.Hour, MinRefresh: time.Minute, HTTPTimeout: time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestTheJarIsFavSessionForSyncedHosts(t *testing.T) {
	h := newHandler(t)
	h.fetchFav = func() (*FavAnswer, error) { return favAnswer("valid"), nil }
	jar, err := h.sync()
	if err != nil {
		t.Fatal(err)
	}
	if header(jar) != "SESSDATA=s; bili_ticket=t" {
		t.Fatalf("jar %q", header(jar))
	}
}

func TestASessionFavFoundInvalidIsNotUsed(t *testing.T) {
	h := newHandler(t)
	h.fetchFav = func() (*FavAnswer, error) { return favAnswer("invalid"), nil }
	jar, err := h.sync()
	if err != nil || len(jar) != 0 {
		t.Fatalf("jar %v, err %v", jar, err)
	}
}

func TestAnUnreachableFavIsAnErrorSoTheJarInHandIsKept(t *testing.T) {
	h := newHandler(t)
	h.fetchFav = func() (*FavAnswer, error) { return nil, errors.New("refused") }
	if _, err := h.sync(); err == nil {
		t.Fatal("expected an error")
	}
}

func TestTheRequestCarriesThisClientsToken(t *testing.T) {
	var seen *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		_, _ = w.Write([]byte(`{"cookies": []}`))
	}))
	defer server.Close()
	answer, err := fetchFav(server.Client(), server.URL+"/api/v2/credentials/bilibili-main", "token")
	if err != nil || len(answer.Cookies) != 0 {
		t.Fatalf("answer %v, err %v", answer, err)
	}
	if seen.Header.Get("Authorization") != "Bearer token" || seen.URL.Path != "/api/v2/credentials/bilibili-main" {
		t.Fatalf("request %v %v", seen.URL, seen.Header)
	}
}

func TestCookieHeaderIsReplacedOutright(t *testing.T) {
	h := newHandler(t)
	h.jar = []cookie{{"SESSDATA", "s"}, {"bili_ticket", "t"}}
	req := httptest.NewRequest(http.MethodGet, "https://api.bilibili.com/x/space/wbi/arc/search", nil)
	req.Header.Set("Cookie", "buvid3=rsshub-made")
	h.Request(req, nil)
	if got := req.Header.Get("Cookie"); got != "SESSDATA=s; bili_ticket=t" {
		t.Fatalf("cookie %q", got)
	}
}

func response(status int, body, contentType string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestSignedOutAndRiskControlBothAskForANewJar(t *testing.T) {
	cases := []struct {
		resp *http.Response
		want bool
	}{
		{response(200, `{"code":-352}`, "application/json"), true},
		{response(200, `{"code":-101}`, "application/json; charset=utf-8"), true},
		{response(200, `{"code":0}`, "application/json"), false},
		{response(412, ``, "text/html"), true},
		{response(200, `{"code":-352}`, "text/html"), false},
	}
	for i, c := range cases {
		if got := riskControlled(c.resp); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
	// The body is still there to forward afterwards.
	resp := response(200, `{"code":0}`, "application/json")
	riskControlled(resp)
	if body, _ := io.ReadAll(resp.Body); string(body) != `{"code":0}` {
		t.Fatalf("body after inspection %q", body)
	}
}

func TestARefusalAsksForASync(t *testing.T) {
	h := newHandler(t)
	req := httptest.NewRequest(http.MethodGet, "https://api.bilibili.com/x/web-interface/nav", nil)
	resp := response(200, `{"code":-352}`, "application/json")
	resp.Request = req
	h.Response(resp, nil)
	select {
	case <-h.refresh:
	default:
		t.Fatal("no refresh requested")
	}
}
