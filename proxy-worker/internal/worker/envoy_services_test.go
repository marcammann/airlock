package worker

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestSDSServerFetchSecretsReturnsLeafForResourceName(t *testing.T) {
	certPEM, keyPEM, err := GenerateCertificateAuthority("airlock test sds ca")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCertificateAuthority(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	log := NewMemoryEventLog()
	server := NewSDSServer(ca, log)

	response, err := server.FetchSecrets(context.Background(), &discoveryv3.DiscoveryRequest{
		ResourceNames: []string{"api.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetTypeUrl() != envoySecretTypeURL {
		t.Fatalf("type_url = %q, want %q", response.GetTypeUrl(), envoySecretTypeURL)
	}
	if len(response.GetResources()) != 1 {
		t.Fatalf("resources = %d, want 1", len(response.GetResources()))
	}

	var secret tlsv3.Secret
	if err := anypb.UnmarshalTo(response.GetResources()[0], &secret, proto.UnmarshalOptions{}); err != nil {
		t.Fatal(err)
	}
	if secret.GetName() != "api.example.test" {
		t.Fatalf("secret name = %q, want api.example.test", secret.GetName())
	}
	tlsCert := secret.GetTlsCertificate()
	if tlsCert == nil {
		t.Fatal("secret missing TLS certificate")
	}
	chainPEM := tlsCert.GetCertificateChain().GetInlineBytes()
	privateKeyPEM := tlsCert.GetPrivateKey().GetInlineBytes()
	if !strings.Contains(string(chainPEM), "BEGIN CERTIFICATE") {
		t.Fatalf("certificate chain = %q, want PEM certificate", string(chainPEM))
	}
	if !strings.Contains(string(privateKeyPEM), "BEGIN PRIVATE KEY") {
		t.Fatalf("private key = %q, want PEM private key", string(privateKeyPEM))
	}

	block, _ := pem.Decode(chainPEM)
	if block == nil {
		t.Fatal("certificate chain PEM did not decode")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("api.example.test"); err != nil {
		t.Fatalf("generated SDS leaf cert hostname verification failed: %v", err)
	}
	if !strings.Contains(strings.Join(log.Entries(), "\n"), "sds fetch resources=api.example.test") {
		t.Fatalf("logs = %q, want SDS fetch entry", log.Entries())
	}
}

func TestSDSServerRefreshesLeafAfterCacheWindow(t *testing.T) {
	certPEM, keyPEM, err := GenerateCertificateAuthority("airlock rotating sds ca")
	if err != nil {
		t.Fatal(err)
	}
	cacheWindow := 2 * time.Second
	ca, err := parseCertificateAuthorityWithCacheWindow(certPEM, keyPEM, cacheWindow)
	if err != nil {
		t.Fatal(err)
	}
	server := NewSDSServer(ca, NewMemoryEventLog())
	request := &discoveryv3.DiscoveryRequest{ResourceNames: []string{"api.example.test"}}

	start := time.Now()
	first := fetchSDSLeafCertificate(t, server, request)
	second := fetchSDSLeafCertificate(t, server, request)
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatalf("serial changed before cache window expired: first=%s second=%s", first.SerialNumber, second.SerialNumber)
	}
	if first.NotAfter.After(start.Add(cacheWindow + 2*time.Second)) {
		t.Fatalf("leaf NotAfter = %s, want within cache window %s", first.NotAfter, cacheWindow)
	}

	ca.mu.Lock()
	cached := ca.cache["api.example.test"]
	cached.expiresAt = time.Now().Add(-time.Millisecond)
	ca.cache["api.example.test"] = cached
	ca.mu.Unlock()

	rotated := fetchSDSLeafCertificate(t, server, request)
	if first.SerialNumber.Cmp(rotated.SerialNumber) == 0 {
		t.Fatalf("serial = %s after cache window, want refreshed leaf", rotated.SerialNumber)
	}
}

func fetchSDSLeafCertificate(t *testing.T, server *SDSServer, request *discoveryv3.DiscoveryRequest) *x509.Certificate {
	t.Helper()
	response, err := server.FetchSecrets(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.GetResources()) != 1 {
		t.Fatalf("resources = %d, want 1", len(response.GetResources()))
	}
	var secret tlsv3.Secret
	if err := anypb.UnmarshalTo(response.GetResources()[0], &secret, proto.UnmarshalOptions{}); err != nil {
		t.Fatal(err)
	}
	tlsCert := secret.GetTlsCertificate()
	if tlsCert == nil {
		t.Fatal("secret missing TLS certificate")
	}
	block, _ := pem.Decode(tlsCert.GetCertificateChain().GetInlineBytes())
	if block == nil {
		t.Fatal("certificate chain PEM did not decode")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
