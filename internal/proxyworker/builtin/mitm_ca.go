package builtin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var randomSerialInt = rand.Int

// CertificateAuthority signs per-destination leaf certificates for HTTPS interception.
type CertificateAuthority struct {
	cert        *x509.Certificate
	key         crypto.Signer
	cache       map[string]cachedLeafCertificate
	cacheWindow time.Duration
	mu          sync.Mutex
}

type cachedLeafCertificate struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

const defaultLeafCertificateCacheWindow = 5 * time.Minute

// LoadCertificateAuthority reads a PEM-encoded CA certificate and private key from disk.
func LoadCertificateAuthority(certPath, keyPath string) (*CertificateAuthority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read MITM CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read MITM CA key: %w", err)
	}
	return ParseCertificateAuthority(certPEM, keyPEM)
}

// LoadTLSClientConfigWithRootCAs builds a TLS client config that trusts the provided CA bundle.
func LoadTLSClientConfigWithRootCAs(certPath string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read upstream CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("upstream CA cert PEM did not contain any certificates")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// ParseCertificateAuthority parses a PEM-encoded CA certificate and signing key.
func ParseCertificateAuthority(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	return parseCertificateAuthorityWithCacheWindow(certPEM, keyPEM, defaultLeafCertificateCacheWindow)
}

func parseCertificateAuthorityWithCacheWindow(certPEM, keyPEM []byte, cacheWindow time.Duration) (*CertificateAuthority, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("mitm CA cert PEM is empty")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse MITM CA cert: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("mitm CA cert is not a CA")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("mitm CA key PEM is empty")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	if cacheWindow <= 0 {
		cacheWindow = defaultLeafCertificateCacheWindow
	}
	return &CertificateAuthority{
		cert:        cert,
		key:         key,
		cache:       map[string]cachedLeafCertificate{},
		cacheWindow: cacheWindow,
	}, nil
}

// GenerateCertificateAuthority creates a short-lived self-signed CA for tests and local demos.
func GenerateCertificateAuthority(commonName string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate MITM CA key: %w", err)
	}
	now := time.Now()
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate MITM CA serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create MITM CA cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

// LeafCertificate returns a cached or newly signed TLS certificate for a host.
func (ca *CertificateAuthority) LeafCertificate(host string) (*tls.Certificate, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return nil, fmt.Errorf("leaf certificate host is required")
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := time.Now()
	if cached, ok := ca.cache[host]; ok && now.Before(cached.expiresAt) {
		return cached.cert, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ca.cacheWindow),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert for %s: %w", host, err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
	}
	ca.cache[host] = cachedLeafCertificate{cert: &tlsCert, expiresAt: now.Add(ca.cacheWindow)}
	return &tlsCert, nil
}

// LeafCertificatePEM returns the leaf certificate chain and private key as PEM.
func (ca *CertificateAuthority) LeafCertificatePEM(host string) ([]byte, []byte, error) {
	cert, err := ca.LeafCertificate(host)
	if err != nil {
		return nil, nil, err
	}
	var certPEM []byte
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// CertPool returns a certificate pool containing the CA certificate.
func (ca *CertificateAuthority) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// TLSCertificate returns the CA certificate as a tls.Certificate.
func (ca *CertificateAuthority) TLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{ca.cert.Raw},
		PrivateKey:  ca.key,
		Leaf:        ca.cert,
	}
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse MITM CA key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("mitm CA key is not a signing key")
	}
	return signer, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := randomSerialInt(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return serial, nil
}
