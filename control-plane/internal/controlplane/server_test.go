package controlplane

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marc/airlock/control-plane/internal/policy"
)

const codeAgentIdentity = "spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"

func TestGetPolicyReturnsCompiledPolicyAndAuditEvent(t *testing.T) {
	var audit bytes.Buffer
	server := newFixtureServer(t, "", &audit)

	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	var compiled policy.CompiledPolicy
	if err := json.NewDecoder(response.Body).Decode(&compiled); err != nil {
		t.Fatal(err)
	}
	if compiled.PolicyName != "code-agent" {
		t.Fatalf("policyName = %q, want code-agent", compiled.PolicyName)
	}
	if compiled.Workload.SPIFFEID != codeAgentIdentity {
		t.Fatalf("spiffeId = %q, want %q", compiled.Workload.SPIFFEID, codeAgentIdentity)
	}

	auditLine := audit.String()
	if !strings.Contains(auditLine, `"outcome":"allowed"`) {
		t.Fatalf("audit line = %s, want allowed outcome", auditLine)
	}
	if !strings.Contains(auditLine, `"policyVersion":"airlock.dev/v1alpha1"`) {
		t.Fatalf("audit line = %s, want policy version", auditLine)
	}
}

func TestGetPolicyIncludesResolvedSecretProviderConfig(t *testing.T) {
	store, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, "", nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var compiled policy.CompiledPolicy
	if err := json.NewDecoder(response.Body).Decode(&compiled); err != nil {
		t.Fatal(err)
	}
	if compiled.SecretProvider == nil || compiled.SecretProvider.Vault == nil {
		t.Fatal("compiled secret provider is nil")
	}
	if got, want := compiled.SecretProvider.Vault.Role, "airlock-demo-code-agent"; got != want {
		t.Fatalf("role = %q, want %q", got, want)
	}
	if got, want := compiled.Egress[0].Rewrites[0].ValueFrom.Mount, "secret"; got != want {
		t.Fatalf("resolved mount = %q, want %q", got, want)
	}
}

func TestGetPolicyAuditDoesNotIncludeSecretRefs(t *testing.T) {
	store, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	server := NewServerWithAuth(store, AuthModeNone, "", &audit)
	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	auditLine := audit.String()
	for _, forbidden := range []string{
		"secret/data/airlock/openai/code-agent",
		"airlock/openai/code-agent",
		"Authorization",
		"Bearer {{secret}}",
	} {
		if strings.Contains(auditLine, forbidden) {
			t.Fatalf("audit line leaked %q: %s", forbidden, auditLine)
		}
	}
}

func TestListAdminPoliciesReturnsSummaries(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/policies", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var out AdminPoliciesResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(out.Policies))
	}
	got := out.Policies[0]
	if got.Name != "code-agent" {
		t.Fatalf("name = %q, want code-agent", got.Name)
	}
	if got.Workload.SPIFFEID != codeAgentIdentity {
		t.Fatalf("spiffeId = %q, want %q", got.Workload.SPIFFEID, codeAgentIdentity)
	}
	if got.EgressCount != 1 || got.RewriteCount != 1 {
		t.Fatalf("counts = egress %d rewrites %d, want 1 and 1", got.EgressCount, got.RewriteCount)
	}
	if len(got.Egress) != 1 || got.Egress[0].Host != "api.example.test" {
		t.Fatalf("egress = %+v, want api.example.test summary", got.Egress)
	}
	if strings.Contains(response.Body.String(), "AIRLOCK_TEST_TOKEN") ||
		strings.Contains(response.Body.String(), "Bearer {{secret}}") ||
		strings.Contains(response.Body.String(), "Authorization") {
		t.Fatalf("admin policy list leaked secret rewrite details: %s", response.Body.String())
	}
}

func TestListAdminPoliciesDevToken(t *testing.T) {
	server := newFixtureServer(t, "secret-dev-token", nil)
	handler := server.Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/admin/policies", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/policies", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer secret-dev-token")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status = %d, want %d", authorized.Code, http.StatusOK)
	}
}

func TestListAdminProxiesReturnsEmptyInventoryUntilHeartbeatStoreExists(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/proxies", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var out AdminProxiesResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Source != "not-configured" {
		t.Fatalf("source = %q, want not-configured", out.Source)
	}
	if len(out.Proxies) != 0 {
		t.Fatalf("proxies = %d, want 0", len(out.Proxies))
	}
}

func TestListAdminProxiesDevToken(t *testing.T) {
	server := newFixtureServer(t, "secret-dev-token", nil)
	handler := server.Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/admin/proxies", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/proxies", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer secret-dev-token")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status = %d, want %d", authorized.Code, http.StatusOK)
	}
}

func TestLoadPolicyStoreErrorsOnMissingSecretProviderRef(t *testing.T) {
	_, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		nil,
	)
	if err == nil {
		t.Fatal("LoadPolicyStoreWithSecretProviderConfigs() error = nil")
	}
	if !strings.Contains(err.Error(), "secretProviderRef airlock-system/default-vault not found") {
		t.Fatalf("error = %q, want missing secret provider ref", err)
	}
}

func TestGetPolicySupportsQueryParameter(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/policies?workload_identity="+url.QueryEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
}

func TestGetPolicyUnknownIdentity(t *testing.T) {
	var audit bytes.Buffer
	server := newFixtureServer(t, "", &audit)
	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape("spiffe://airlock.local/ns/demo/sa/unknown"), nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if !strings.Contains(audit.String(), `"outcome":"not_found"`) {
		t.Fatalf("audit line = %s, want not_found outcome", audit.String())
	}
}

func TestGetPolicyDevToken(t *testing.T) {
	server := newFixtureServer(t, "secret-dev-token", nil)
	handler := server.Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	authorizedRequest.Header.Set("Authorization", "Bearer secret-dev-token")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status = %d, want %d", authorized.Code, http.StatusOK)
	}
}

func TestGetPolicySPIFFEAuthRequiresMatchingIdentity(t *testing.T) {
	handler := newFixtureServerWithAuth(t, AuthModeSPIFFE, "", nil).Handler()

	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{CertificateWithSPIFFEID(codeAgentIdentity)},
	}
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
}

func TestGetPolicySPIFFEAuthRejectsMismatchedIdentity(t *testing.T) {
	handler := newFixtureServerWithAuth(t, AuthModeSPIFFE, "", nil).Handler()

	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{CertificateWithSPIFFEID("spiffe://airlock.local/ns/demo/sa/other/component/airlock-proxy-worker")},
	}
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestGetPolicySPIFFEAuthRejectsMissingSVID(t *testing.T) {
	handler := newFixtureServerWithAuth(t, AuthModeSPIFFE, "", nil).Handler()
	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestReadyRequiresPolicy(t *testing.T) {
	server := NewServer(&PolicyStore{byWorkload: map[string]policy.CompiledPolicy{}}, "", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func newFixtureServer(t *testing.T, devToken string, audit *bytes.Buffer) *Server {
	authMode := AuthModeNone
	if devToken != "" {
		authMode = AuthModeDevToken
	}
	return newFixtureServerWithAuth(t, authMode, devToken, audit)
}

func newFixtureServerWithAuth(t *testing.T, authMode AuthMode, devToken string, audit *bytes.Buffer) *Server {
	t.Helper()

	store, err := LoadPolicyStore([]string{filepath.Join("..", "..", "..", "fixtures", "policies", "valid.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	var auditWriter io.Writer
	if audit != nil {
		auditWriter = audit
	}
	return NewServerWithAuth(store, authMode, devToken, auditWriter)
}

func CertificateWithSPIFFEID(rawID string) *x509.Certificate {
	parsed, err := url.Parse(rawID)
	if err != nil {
		return &x509.Certificate{}
	}
	return &x509.Certificate{URIs: []*url.URL{parsed}}
}
