// Package flow holds what the proxy and the handlers share about one request.
package flow

import (
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
)

// Handler rewrites the traffic of the hosts it names.
//
// Request runs before anything is sent upstream. Returning a response answers
// the client directly and the origin is never contacted; the response hook is
// then skipped, because there is nothing upstream to react to.
//
// Response runs on what the origin answered and may replace it.
type Handler interface {
	Name() string
	// Hosts are domain suffixes: "example.com" matches it and every subdomain.
	Hosts() []string
	Request(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response)
	Response(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response
}

// State is kept on the goproxy context from the request hook to the response
// hook of one request.
type State struct {
	Handler   Handler
	Synthetic bool
	// Retried marks a request a handler has already answered a second time,
	// so a refusal of the retry is not retried again.
	Retried bool
}

// StateOf returns the request's state, or a fresh one when there is none.
func StateOf(ctx *goproxy.ProxyCtx) *State {
	if ctx != nil {
		if state, ok := ctx.UserData.(*State); ok {
			return state
		}
	}
	return &State{}
}

// MatchSuffix reports whether host is suffix or a subdomain of it.
func MatchSuffix(host, suffix string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// SiteOf returns the first suffix host belongs to, or "".
func SiteOf(host string, suffixes []string) string {
	for _, suffix := range suffixes {
		if MatchSuffix(host, suffix) {
			return suffix
		}
	}
	return ""
}
