package httpx

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestDecode(t *testing.T) {
	plain := []byte(`{"code":200,"results":{}}`)

	var gz, zl, br bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(plain)
	_ = w.Close()
	z := zlib.NewWriter(&zl)
	_, _ = z.Write(plain)
	_ = z.Close()
	b := brotli.NewWriter(&br)
	_, _ = b.Write(plain)
	_ = b.Close()

	for encoding, body := range map[string][]byte{"gzip": gz.Bytes(), "deflate": zl.Bytes(), "br": br.Bytes(), "": plain} {
		got, err := Decode(body, encoding)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("%q: got %q, %v", encoding, got, err)
		}
	}

	// A body that does not decode comes back unchanged, with the error.
	got, err := Decode([]byte("not gzip"), "gzip")
	if err == nil || string(got) != "not gzip" {
		t.Errorf("bad gzip: got %q, %v", got, err)
	}
}
