package worker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failingSecretProvider struct {
	err error
}

func (p failingSecretProvider) Resolve(SecretRef) (string, error) {
	return "", p.err
}

func TestVaultSecretProviderResolveFailsWhenCacheEntryExpired(t *testing.T) {
	key := vaultSecretKey{Mount: "secret", Path: "airlock/openai/code-agent", Key: "api_key"}
	provider := &VaultSecretProvider{
		cache: map[vaultSecretKey]cachedSecret{
			key: {Value: "expired-token", ExpiresAt: time.Now().Add(-time.Second)},
		},
	}

	_, err := provider.Resolve(SecretRef{
		Provider: "vault",
		Mount:    key.Mount,
		Engine:   "kv-v2",
		Path:     key.Path,
		Key:      key.Key,
	})
	if err == nil {
		t.Fatal("Resolve() error = nil, want expired cache error")
	}
	if !strings.Contains(err.Error(), "cache entry expired") {
		t.Fatalf("error = %q, want cache entry expired", err)
	}
}

func TestVaultSecretCacheTTLTracksVaultTokenLease(t *testing.T) {
	ttl, err := vaultSecretCacheTTL(2)
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 2*time.Second {
		t.Fatalf("ttl = %s, want Vault token lease", ttl)
	}

	ttl, err = vaultSecretCacheTTL(20 * 60)
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 5*time.Minute {
		t.Fatalf("ttl = %s, want worker cache cap", ttl)
	}
}

func TestVaultSecretCacheTTLRejectsUnknownTokenLease(t *testing.T) {
	_, err := vaultSecretCacheTTL(0)
	if err == nil {
		t.Fatal("vaultSecretCacheTTL() error = nil, want non-positive lease failure")
	}
	if !strings.Contains(err.Error(), "non-positive lease_duration") {
		t.Fatalf("error = %q, want non-positive lease_duration", err)
	}
}

func TestVaultReadKV2Non200FailsClosed(t *testing.T) {
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(vault.Close)

	_, err := vaultReadKV2(context.Background(), vault.URL, "vault-token", vaultSecretKey{
		Mount: "secret",
		Path:  "airlock/openai/code-agent",
		Key:   "api_key",
	})
	if err == nil {
		t.Fatal("vaultReadKV2() error = nil, want non-200 error")
	}
	if !strings.Contains(err.Error(), "failed HTTP 503") {
		t.Fatalf("error = %q, want HTTP 503", err)
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

	_, err := NewControlPlanePolicyProvider(controlPlane.URL, testWorkloadIdentity, "").LoadSPIFFEMTLS(
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

func TestSPIFFEVaultAuthFailsBeforeVaultRequestWhenWorkloadAPIMissing(t *testing.T) {
	vaultRequests := make(chan struct{}, 1)
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		vaultRequests <- struct{}{}
		http.Error(w, "unexpected vault request", http.StatusInternalServerError)
	}))
	t.Cleanup(vault.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	t.Cleanup(cancel)
	missingSocket := "unix://" + filepath.Join(t.TempDir(), "missing-spire-agent.sock")

	_, err := NewVaultSecretProvider(ctx, testVaultPolicy(vault.URL), missingSocket)
	if err == nil {
		t.Fatal("NewVaultSecretProvider() error = nil, want missing workload API error")
	}
	if !strings.Contains(err.Error(), "SPIFFE") {
		t.Fatalf("error = %q, want SPIFFE workload API failure", err)
	}
	select {
	case <-vaultRequests:
		t.Fatal("Vault received request despite missing workload API")
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

func testVaultPolicy(vaultAddress string) CompiledPolicy {
	policy := testPolicy("api.example.test", 80)
	policy.SecretProvider = &CompiledSecretProvider{
		Provider: "vault",
		Vault: &CompiledVaultProvider{
			Address:   vaultAddress,
			AuthMount: "jwt",
			Audience:  "vault",
			Role:      "airlock-demo-code-agent",
		},
	}
	policy.Egress[0].Rewrites[0].ValueFrom = SecretRef{
		Provider: "vault",
		Mount:    "secret",
		Engine:   "kv-v2",
		Path:     "airlock/openai/code-agent",
		Key:      "api_key",
	}
	return policy
}
