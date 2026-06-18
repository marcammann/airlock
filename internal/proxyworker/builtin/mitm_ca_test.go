package builtin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadCertificateAuthorityRejectsInvalidFiles(t *testing.T) {
	certPEM, keyPEM, err := GenerateCertificateAuthority("airlock test mitm ca")
	if err != nil {
		t.Fatal(err)
	}
	nonCACertPEM, _, err := generateTestCertificate(t, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		certPEM []byte
		keyPEM  []byte
		wantErr string
	}{
		{name: "bad cert PEM", certPEM: []byte("not a pem"), keyPEM: keyPEM, wantErr: "cert PEM is empty"},
		{name: "non CA cert", certPEM: nonCACertPEM, keyPEM: keyPEM, wantErr: "cert is not a CA"},
		{name: "bad key PEM", certPEM: certPEM, keyPEM: []byte("not a pem"), wantErr: "key PEM is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath := filepath.Join(dir, "ca.crt")
			keyPath := filepath.Join(dir, "ca.key")
			if err := os.WriteFile(certPath, tt.certPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, tt.keyPEM, 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := LoadCertificateAuthority(certPath, keyPath)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadCertificateAuthority() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestRandomSerialFailurePropagates(t *testing.T) {
	certPEM, keyPEM, err := GenerateCertificateAuthority("airlock test mitm ca")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCertificateAuthority(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	previous := randomSerialInt
	randomSerialInt = func(io.Reader, *big.Int) (*big.Int, error) {
		return nil, errors.New("entropy unavailable")
	}
	t.Cleanup(func() { randomSerialInt = previous })

	_, err = ca.LeafCertificate("example.test")
	if err == nil {
		t.Fatal("LeafCertificate() error = nil, want random serial failure")
	}
	if !strings.Contains(err.Error(), "generate leaf serial") {
		t.Fatalf("error = %q, want leaf serial failure", err)
	}
}

func generateTestCertificate(t *testing.T, isCA bool) ([]byte, []byte, error) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "airlock test cert"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}
