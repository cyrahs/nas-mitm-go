// Package httpx has the small HTTP helpers the handlers share.
package httpx

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
)

// NewResponse builds a complete response to answer req with.
func NewResponse(req *http.Request, status int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// Text answers with a plain body and the given content type ("" for none).
func Text(req *http.Request, status int, contentType string, body []byte) *http.Response {
	header := http.Header{}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return NewResponse(req, status, header, body)
}

// Decode undoes a Content-Encoding. It returns the body unchanged, with the
// error, when the encoding is unknown or the body does not decode.
func Decode(body []byte, encoding string) ([]byte, error) {
	var reader io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, err
		}
		reader = r
	case "deflate":
		r, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, err
		}
		reader = r
	case "br":
		reader = brotli.NewReader(bytes.NewReader(body))
	default:
		return body, &UnknownEncodingError{encoding}
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return body, err
	}
	return decoded, nil
}

// UnknownEncodingError is returned by Decode for encodings it cannot undo.
type UnknownEncodingError struct{ Encoding string }

func (e *UnknownEncodingError) Error() string { return "unknown content encoding " + e.Encoding }

// ReadBody reads a response body fully and puts an identical one back, so
// the response can still be forwarded.
func ReadBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil || resp.Body == http.NoBody {
		return nil, nil
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return body, err
}

// Transport returns a client transport. proxyURL "" means a direct
// connection. keepAlive false gives every request a connection of its own.
func Transport(proxyURL string, keepAlive bool) (*http.Transport, error) {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   4,
		ExpectContinueTimeout: time.Second,
		DisableKeepAlives:     !keepAlive,
	}
	if proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	return transport, nil
}
