package ca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateLoadAndSign(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v, want 0600", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Join(dir, CertFile)); info.Mode().Perm() != 0o644 {
		t.Fatalf("cert mode %v, want 0644", info.Mode().Perm())
	}

	authority, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := authority.Leaf("api.manga2026.com")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := authority.Leaf("api.manga2026.com")
	if again != leaf {
		t.Fatal("leaf not cached")
	}

	roots := x509.NewCertPool()
	roots.AddCert(authority.Certificate())
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "api.manga2026.com", Roots: roots}); err != nil {
		t.Fatalf("leaf does not verify against the CA: %v", err)
	}

	config, err := authority.TLSConfig("www.javlibrary.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" {
		t.Fatalf("NextProtos %v, want only http/1.1", config.NextProtos)
	}
}
