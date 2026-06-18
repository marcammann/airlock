// Package proxyworker_test exercises proxy-worker behavior through public test adapters.
package proxyworker_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marcammann/airlock/internal/telemetry"
	globalotel "go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type failingSecretProvider struct {
	err error
}

func (p failingSecretProvider) Resolve(SecretRef) (string, error) {
	return "", p.err
}

func TestNoSecretsInLogs(t *testing.T) {
	const secret = "super-secret-token"
	const secretCoordinate = "/airlock/secrets/openai-token"
	var logOutput bytes.Buffer
	eventLog := NewEventLog(&logOutput)

	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	previousTracerProvider := globalotel.GetTracerProvider()
	globalotel.SetTracerProvider(tracerProvider)
	t.Cleanup(func() {
		_ = tracerProvider.Shutdown(context.Background())
		globalotel.SetTracerProvider(previousTracerProvider)
	})

	policy := testPolicy("api.example.test", 80)
	policy.Egress[0].Rewrites[0].ValueFrom = SecretRef{Provider: "file", File: secretCoordinate}

	decision, err := EvaluateExtProcHeadersWithContext(
		context.Background(),
		policy,
		[]Header{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "api.example.test"},
			{Name: ":path", Value: "/v1/models"},
		},
		staticSecretProvider{value: secret},
		eventLog,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Continue {
		t.Fatalf("decision = %+v, want continue", decision)
	}

	logs := logOutput.String() + strings.Join(eventLog.Entries(), "\n")
	if strings.Contains(logs, secret) {
		t.Fatalf("logs leaked secret value: %q", logs)
	}
	if strings.Contains(logs, secretCoordinate) {
		t.Fatalf("logs leaked secret coordinate: %q", logs)
	}
	if !strings.Contains(logs, Redacted) {
		t.Fatalf("logs = %q, want redacted marker", logs)
	}

	metricsResponse := httptest.NewRecorder()
	telemetry.MetricsHandler().ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(metricsResponse.Body.String(), secret) {
		t.Fatalf("metrics leaked secret value: %q", metricsResponse.Body.String())
	}
	if strings.Contains(metricsResponse.Body.String(), secretCoordinate) {
		t.Fatalf("metrics leaked secret coordinate: %q", metricsResponse.Body.String())
	}

	for _, span := range spanRecorder.Ended() {
		for _, attr := range span.Attributes() {
			if strings.Contains(attr.Value.AsString(), secret) {
				t.Fatalf("span %q attribute %s leaked secret value", span.Name(), attr.Key)
			}
			if strings.Contains(attr.Value.AsString(), secretCoordinate) {
				t.Fatalf("span %q attribute %s leaked secret coordinate", span.Name(), attr.Key)
			}
		}
	}
}

func TestSPIFFEPolicyFetchFailsBeforeControlPlaneRequestWhenWorkloadAPIMissing(t *testing.T) {
	controlPlaneRequests := make(chan struct{}, 1)
	controlPlane := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		controlPlaneRequests <- struct{}{}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(controlPlane.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	t.Cleanup(cancel)
	missingSocket := "unix://" + filepath.Join(t.TempDir(), "missing-spire-agent.sock")

	_, err := NewControlPlanePolicyProvider(controlPlane.URL, testWorkloadIdentity).LoadSPIFFEMTLS(
		ctx,
		"spiffe://airlock.local/ns/airlock-system/sa/airlock-control-plane",
		missingSocket,
	)
	if err == nil {
		t.Fatal("LoadSPIFFEMTLS() error = nil, want missing workload API error")
	}
	if !strings.Contains(err.Error(), "SPIFFE") {
		t.Fatalf("error = %q, want SPIFFE workload API failure", err)
	}
	select {
	case <-controlPlaneRequests:
		t.Fatal("control plane received request despite missing workload API")
	default:
	}
}

func TestBuiltinProxySecretFailureDoesNotReachUpstream(t *testing.T) {
	upstreamAddr, upstreamRequests := startUpstream(t)
	log := NewMemoryEventLog()
	proxy := NewProxyServer(
		testPolicy("127.0.0.1", uint16(upstreamAddr.Port)),
		failingSecretProvider{err: fmt.Errorf("vault unavailable")},
		log,
	)
	proxyAddr := startProxy(t, proxy)

	response := sendProxyRequest(t, proxyAddr, fmt.Sprintf(
		"GET http://127.0.0.1:%d/v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n",
		upstreamAddr.Port,
		upstreamAddr.Port,
	))

	if !strings.HasPrefix(response, "HTTP/1.1 502 Bad Gateway") {
		t.Fatalf("response = %q, want 502", response)
	}
	select {
	case request := <-upstreamRequests:
		t.Fatalf("upstream received request despite secret failure: %q", request)
	case <-time.After(100 * time.Millisecond):
	}
	logs := strings.Join(log.Entries(), "\n")
	if !strings.Contains(logs, "dependency=secret") {
		t.Fatalf("logs = %q, want secret dependency failure", logs)
	}
}

func TestRewriteRejectsCRLFInSecretValue(t *testing.T) {
	upstreamAddr, upstreamRequests := startUpstream(t)
	log := NewMemoryEventLog()
	proxy := NewProxyServer(
		testPolicy("127.0.0.1", uint16(upstreamAddr.Port)),
		staticSecretProvider{value: "foo\r\nX-Evil: bar"},
		log,
	)
	proxyAddr := startProxy(t, proxy)

	response := sendProxyRequest(t, proxyAddr, fmt.Sprintf(
		"GET http://127.0.0.1:%d/v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n",
		upstreamAddr.Port,
		upstreamAddr.Port,
	))

	if !strings.HasPrefix(response, "HTTP/1.1 502 Bad Gateway") {
		t.Fatalf("response = %q, want 502", response)
	}
	select {
	case request := <-upstreamRequests:
		t.Fatalf("upstream received request despite CRLF rewrite value: %q", request)
	case <-time.After(100 * time.Millisecond):
	}
	logs := strings.Join(log.Entries(), "\n")
	if !strings.Contains(logs, "rewrite value contains CRLF") {
		t.Fatalf("logs = %q, want CRLF rewrite denial", logs)
	}
	if strings.Contains(logs, "X-Evil") {
		t.Fatalf("logs leaked injected header content: %q", logs)
	}
}

func TestUpstreamResponseOverLimitIsRejected(t *testing.T) {
	body := strings.Repeat("x", 32)
	upstreamAddr := startUpstreamResponse(t, []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body),
		body,
	)))
	log := NewMemoryEventLog()
	proxy := NewProxyServerWithOptions(
		testPolicy("127.0.0.1", uint16(upstreamAddr.Port)),
		staticSecretProvider{value: "test-token"},
		log,
		ProxyServerOptions{MaxResponseBytes: 8},
	)
	proxyAddr := startProxy(t, proxy)

	response := sendProxyRequest(t, proxyAddr, fmt.Sprintf(
		"GET http://127.0.0.1:%d/v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n",
		upstreamAddr.Port,
		upstreamAddr.Port,
	))

	if !strings.HasPrefix(response, "HTTP/1.1 502 Bad Gateway") {
		t.Fatalf("response = %q, want 502", response)
	}
	logs := strings.Join(log.Entries(), "\n")
	if !strings.Contains(logs, "reason=response_too_large") {
		t.Fatalf("logs = %q, want response_too_large", logs)
	}
}

func TestUpstreamHangTimesOut(t *testing.T) {
	upstreamAddr := startHangingUpstream(t)
	log := NewMemoryEventLog()
	proxy := NewProxyServerWithOptions(
		testPolicy("127.0.0.1", uint16(upstreamAddr.Port)),
		staticSecretProvider{value: "test-token"},
		log,
		ProxyServerOptions{UpstreamResponseHeaderTimeout: 100 * time.Millisecond},
	)
	proxyAddr := startProxy(t, proxy)

	start := time.Now()
	response := sendProxyRequest(t, proxyAddr, fmt.Sprintf(
		"GET http://127.0.0.1:%d/v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n",
		upstreamAddr.Port,
		upstreamAddr.Port,
	))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("proxy response took %s, want timeout response within 2s", elapsed)
	}
	if !strings.HasPrefix(response, "HTTP/1.1 504 Gateway Timeout") {
		t.Fatalf("response = %q, want 504", response)
	}
	logs := strings.Join(log.Entries(), "\n")
	if !strings.Contains(logs, "reason=upstream_timeout") {
		t.Fatalf("logs = %q, want upstream_timeout", logs)
	}
}

func TestParseCertificateAuthorityRejectsInvalidInputs(t *testing.T) {
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
		{name: "empty cert", certPEM: nil, keyPEM: keyPEM, wantErr: "cert PEM is empty"},
		{name: "non ca cert", certPEM: nonCACertPEM, keyPEM: keyPEM, wantErr: "cert is not a CA"},
		{name: "empty key", certPEM: certPEM, keyPEM: nil, wantErr: "key PEM is empty"},
		{name: "bad key", certPEM: certPEM, keyPEM: []byte("not a pem"), wantErr: "key PEM is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCertificateAuthority(tt.certPEM, tt.keyPEM)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParseCertificateAuthority() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadCertificateAuthorityReadsFiles(t *testing.T) {
	certPEM, keyPEM, err := GenerateCertificateAuthority("airlock test mitm ca")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadCertificateAuthority(certPath, keyPath); err != nil {
		t.Fatalf("LoadCertificateAuthority() error = %v, want nil", err)
	}
	if _, err := LoadCertificateAuthority(filepath.Join(dir, "missing.crt"), keyPath); err == nil {
		t.Fatal("LoadCertificateAuthority() error = nil, want missing cert error")
	}
}

func startUpstreamResponse(t *testing.T, response []byte) *net.TCPAddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = readHTTPRequestBytes(conn)
		_, _ = conn.Write(response)
	}()

	return listener.Addr().(*net.TCPAddr)
}

func startHangingUpstream(t *testing.T) *net.TCPAddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = listener.Close()
	})

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = readHTTPRequestBytes(conn)
		<-done
	}()

	return listener.Addr().(*net.TCPAddr)
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

func TestExtProcSecretFailureDoesNotReturnMutation(t *testing.T) {
	log := NewMemoryEventLog()
	decision, err := EvaluateExtProcHeaders(
		testPolicy("api.example.test", 80),
		[]Header{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "api.example.test"},
			{Name: ":path", Value: "/v1/models"},
		},
		failingSecretProvider{err: fmt.Errorf("vault unavailable")},
		log,
	)
	if err == nil {
		t.Fatal("EvaluateExtProcHeaders() error = nil, want secret failure")
	}
	if decision.Continue || decision.Deny || len(decision.Mutations) != 0 {
		t.Fatalf("decision = %+v, want no continue, deny, or mutations", decision)
	}
	if strings.Contains(strings.Join(log.Entries(), "\n"), "allowed ext_proc request") {
		t.Fatalf("logs = %q, want no allowed request log", log.Entries())
	}
	if !strings.Contains(strings.Join(log.Entries(), "\n"), "dependency=secret") {
		t.Fatalf("logs = %q, want secret dependency failure", log.Entries())
	}
}

func TestExtProcPolicyRevocationDeniesPreviouslyAllowedDestination(t *testing.T) {
	oldPolicy := testPolicyWithScheme("https", "old.example.test", 443)
	revokedPolicy := testPolicyWithScheme("https", "new.example.test", 443)
	headers := []Header{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "old.example.test"},
		{Name: ":path", Value: "/v1/models"},
	}

	oldDecision, err := EvaluateExtProcHeaders(oldPolicy, headers, staticSecretProvider{value: "test-token"}, NewMemoryEventLog())
	if err != nil {
		t.Fatal(err)
	}
	if !oldDecision.Continue {
		t.Fatalf("old decision = %+v, want continue", oldDecision)
	}

	log := NewMemoryEventLog()
	revokedDecision, err := EvaluateExtProcHeaders(revokedPolicy, headers, staticSecretProvider{value: "test-token"}, log)
	if err != nil {
		t.Fatal(err)
	}
	want := ExtProcDecision{
		Deny:    true,
		Status:  403,
		Body:    "egress denied",
		Details: "airlock_egress_denied",
	}
	if !revokedDecision.Equal(want) {
		t.Fatalf("revoked decision = %+v, want %+v", revokedDecision, want)
	}
	if strings.Contains(strings.Join(log.Entries(), "\n"), "test-token") {
		t.Fatalf("revocation logs leaked secret: %q", log.Entries())
	}
}
