// Package ca mints the Pod-local certificate authority and the per-host leaf
// certificates signed by it.
//
// The CA lives and dies with the Pod: an init container writes it to an
// emptyDir, the client container trusts the public half, and the proxy reads
// both. Nothing about it is kept in Git or survives a restart.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// File names inside the certificate directory.
const (
	CertFile = "ca.crt"
	KeyFile  = "ca.key"
)

// Authority signs leaf certificates for intercepted hosts.
type Authority struct {
	cert    *x509.Certificate
	certDER []byte
	key     crypto.Signer

	// One leaf key for every host, as mitmproxy does: generating a key per
	// host costs time and memory and buys nothing for a Pod-local CA.
	leafKey *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// Generate writes a fresh CA into dir. The certificate is world-readable so
// other containers can trust it; the key is readable only by its owner.
func Generate(dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "nas-mitm Pod CA", Organization: []string{"nas-mitm"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeFile(filepath.Join(dir, KeyFile), keyPEM, 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, CertFile), certPEM, 0o644)
}

// writeFile replaces path and then sets the mode explicitly, since the umask
// would otherwise decide it.
func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// Load reads the CA that Generate wrote.
func Load(dir string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("no certificate in " + CertFile)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("no key in " + KeyFile)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported CA key type %T", parsed)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authority{
		cert:    cert,
		certDER: certBlock.Bytes,
		key:     signer,
		leafKey: leafKey,
		cache:   map[string]*tls.Certificate{},
	}, nil
}

// Certificate returns the CA certificate, for clients in tests.
func (a *Authority) Certificate() *x509.Certificate { return a.cert }

// Leaf returns a certificate for host, signing one on first use.
func (a *Authority) Leaf(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cert, ok := a.cache[host]; ok && time.Now().Before(cert.Leaf.NotAfter.Add(-24*time.Hour)) {
		return cert, nil
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, a.certDER},
		PrivateKey:  a.leafKey,
		Leaf:        leaf,
	}
	a.cache[host] = cert
	return cert, nil
}

// TLSConfig is the server side of an intercepted connection. It offers only
// HTTP/1.1, so every client falls back to it and the handlers see one
// protocol.
func (a *Authority) TLSConfig(host string) (*tls.Config, error) {
	cert, err := a.Leaf(host)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}
