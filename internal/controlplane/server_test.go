package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/marcammann/airlock/internal/policy"
)

const codeAgentIdentity = "spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"

func TestGetPolicyReturnsCompiledPolicyAndAuditEvent(t *testing.T) {
	var audit bytes.Buffer
	server := newFixtureServer(t, "", &audit)

	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	server.WorkerHandler().ServeHTTP(response, request)

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
	if !strings.Contains(auditLine, `"effectivePolicyVersion":"airlock.dev/v1alpha1"`) {
		t.Fatalf("audit line = %s, want effective policy version", auditLine)
	}
}

func TestGetPolicyIncludesResolvedSecretProviderConfig(t *testing.T) {
	store, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent-vault.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServerWithOptions(store, ServerOptions{
		WorkerAuthMode:       AuthModeNone,
		AdminAuthMode:        AuthModeNone,
		AllowInsecureDevAuth: true,
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	server.WorkerHandler().ServeHTTP(response, request)

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
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent-vault.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	server := NewServerWithOptions(store, ServerOptions{
		WorkerAuthMode:       AuthModeNone,
		AdminAuthMode:        AuthModeNone,
		AllowInsecureDevAuth: true,
		Audit:                &audit,
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	server.WorkerHandler().ServeHTTP(response, request)

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

func TestListAdminWorkloadsReturnsSummaries(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	response := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var out AdminWorkloadsResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Workloads) != 1 {
		t.Fatalf("workloads = %d, want 1", len(out.Workloads))
	}
	got := out.Workloads[0]
	if got.Name != "code-agent" {
		t.Fatalf("name = %q, want code-agent", got.Name)
	}
	if len(got.PolicyRefs) != 1 || got.PolicyRefs[0].Name != "openai-api" {
		t.Fatalf("policyRefs = %+v, want openai-api", got.PolicyRefs)
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
		t.Fatalf("admin workload list leaked secret rewrite details: %s", response.Body.String())
	}
}

func TestListAdminPoliciesReturnsReusablePolicySummaries(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/policies", nil)
	response := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(response, request)

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
	if got.Name != "openai-api" || got.Namespace != "airlock-system" {
		t.Fatalf("policy = %+v, want airlock-system/openai-api", got)
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

func TestAdminAuthNoneRequiresInsecureDevServerOption(t *testing.T) {
	store, err := LoadPolicyStore(
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServerWithOptions(store, ServerOptions{
		WorkerAuthMode: AuthModeSPIFFE,
		AdminAuthMode:  AuthModeNone,
		Audit:          io.Discard,
	})

	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestListAdminWorkloadsIncludesProxyInstances(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	now := time.Now().UTC()
	body, err := json.Marshal(ProxyHeartbeatRequest{
		ID:                "10.42.0.17",
		WorkloadIdentity:  codeAgentIdentity,
		WorkloadName:      "code-agent",
		EffectiveVersion:  "airlock.dev/v1alpha1",
		PolicyFetched:     true,
		ProxyType:         "http:builtin",
		HeartbeatInterval: "10s",
		PodNamespace:      "demo",
		PodName:           "code-agent-123",
		LastPolicyFetchAt: &now,
		LastDecisionAt:    &now,
		Decisions:         DecisionCounts{Allowed: 2, Denied: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := httptest.NewRequest(http.MethodPost, "/v1/proxies/heartbeat", bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, heartbeat)
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	response = httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var out AdminWorkloadsResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Workloads) != 1 {
		t.Fatalf("workloads = %d, want 1", len(out.Workloads))
	}
	got := out.Workloads[0]
	if got.InstanceCount != 1 || got.ActiveInstances != 1 || got.Status != "active" {
		t.Fatalf("workload instances = count %d active %d status %q, want one active", got.InstanceCount, got.ActiveInstances, got.Status)
	}
	if len(got.Instances) != 1 || got.Instances[0].ID != "10.42.0.17" {
		t.Fatalf("instances = %+v, want 10.42.0.17", got.Instances)
	}
	if got.Decisions.Allowed != 2 || got.Decisions.Denied != 1 {
		t.Fatalf("decisions = %+v, want allowed=2 denied=1", got.Decisions)
	}
}

func TestListAdminWorkloadsIncludesRecentAlerts(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	now := time.Now().UTC()
	server.mu.Lock()
	server.events = []AdminEvent{
		{ID: "denied", ObservedAt: now, Type: "egress.denied", Count: 3, ProxyID: "10.42.0.17", WorkloadIdentity: codeAgentIdentity},
		{ID: "proxy-error", ObservedAt: now.Add(-time.Hour), Type: "proxy.error", Count: 2, ProxyID: "10.42.0.17", WorkloadIdentity: codeAgentIdentity},
		{ID: "old-denied", ObservedAt: now.Add(-25 * time.Hour), Type: "egress.denied", Count: 99, ProxyID: "10.42.0.17", WorkloadIdentity: codeAgentIdentity},
	}
	server.mu.Unlock()

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var out AdminWorkloadsResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Workloads) != 1 {
		t.Fatalf("workloads = %d, want 1", len(out.Workloads))
	}
	got := out.Workloads[0].Alerts
	if got.Denied != 3 || got.ProxyError != 2 || got.Total != 5 {
		t.Fatalf("alerts = %+v, want denied=3 proxyError=2 total=5", got)
	}
}

func TestListAdminWorkloadsDevToken(t *testing.T) {
	server := newFixtureServer(t, "secret-dev-token", nil)
	handler := server.AdminHandler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer secret-dev-token")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status = %d, want %d", authorized.Code, http.StatusOK)
	}
}

func TestListAdminProxiesReturnsGroupedHeartbeatInventory(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	now := time.Now().UTC()
	firstBody, err := json.Marshal(ProxyHeartbeatRequest{
		ID:                "proxy-1",
		WorkloadIdentity:  codeAgentIdentity,
		WorkloadName:      "code-agent",
		EffectiveVersion:  "airlock.dev/v1alpha1",
		PolicyFetched:     true,
		ProxyType:         "http:builtin",
		HeartbeatInterval: "10s",
		PodNamespace:      "demo",
		PodName:           "code-agent-123",
		LastPolicyFetchAt: &now,
		LastDecisionAt:    &now,
		Decisions:         DecisionCounts{Allowed: 2, Denied: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := httptest.NewRequest(http.MethodPost, "/v1/proxies/heartbeat", bytes.NewReader(firstBody))
	response := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, heartbeat)
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	secondBody, err := json.Marshal(ProxyHeartbeatRequest{
		ID:                "proxy-2",
		WorkloadIdentity:  codeAgentIdentity,
		WorkloadName:      "code-agent",
		EffectiveVersion:  "airlock.dev/v1alpha1",
		PolicyFetched:     true,
		ProxyType:         "http:builtin",
		HeartbeatInterval: "10s",
		PodNamespace:      "demo",
		PodName:           "code-agent-456",
		LastPolicyFetchAt: &now,
		LastDecisionAt:    &now,
		Decisions:         DecisionCounts{Allowed: 3, Denied: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat = httptest.NewRequest(http.MethodPost, "/v1/proxies/heartbeat", bytes.NewReader(secondBody))
	response = httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, heartbeat)
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/proxies", nil)
	response = httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var out AdminProxiesResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Source != "control-plane-heartbeat" {
		t.Fatalf("source = %q, want control-plane-heartbeat", out.Source)
	}
	if len(out.Proxies) != 1 {
		t.Fatalf("proxies = %d, want 1", len(out.Proxies))
	}
	got := out.Proxies[0]
	if got.WorkloadIdentity != codeAgentIdentity || got.WorkloadName != "code-agent" || got.Status != "active" {
		t.Fatalf("proxy = %+v, want active code-agent proxy", got)
	}
	if got.InstanceCount != 2 || got.ActiveInstances != 2 || len(got.Instances) != 2 {
		t.Fatalf("instances = count %d active %d list %+v, want two active instances", got.InstanceCount, got.ActiveInstances, got.Instances)
	}
	if got.Decisions.Allowed != 5 || got.Decisions.Denied != 5 {
		t.Fatalf("decisions = %+v, want allowed=5 denied=5", got.Decisions)
	}
	if got.Instances[0].ID != "proxy-1" || got.Instances[1].ID != "proxy-2" {
		t.Fatalf("instances = %+v, want sorted proxy-1/proxy-2", got.Instances)
	}
}

func TestProxyHeartbeatRejectsMissingHeartbeatInterval(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	body, err := json.Marshal(ProxyHeartbeatRequest{
		ID:               "proxy-1",
		WorkloadIdentity: codeAgentIdentity,
		WorkloadName:     "code-agent",
		EffectiveVersion: "airlock.dev/v1alpha1",
		PolicyFetched:    true,
		ProxyType:        "http:builtin",
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := httptest.NewRequest(http.MethodPost, "/v1/proxies/heartbeat", bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, heartbeat)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
}

func TestListAdminProxiesUsesHeartbeatStaleThreshold(t *testing.T) {
	server := newFixtureServerWithOptions(t, ServerOptions{HeartbeatStaleThreshold: 2})
	now := time.Now().UTC()
	body, err := json.Marshal(ProxyHeartbeatRequest{
		ID:                "proxy-1",
		WorkloadIdentity:  codeAgentIdentity,
		WorkloadName:      "code-agent",
		EffectiveVersion:  "airlock.dev/v1alpha1",
		PolicyFetched:     true,
		ProxyType:         "http:builtin",
		HeartbeatInterval: "10s",
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := httptest.NewRequest(http.MethodPost, "/v1/proxies/heartbeat", bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, heartbeat)
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	statuses := server.proxyStatuses(now.Add(21 * time.Second))
	if len(statuses) != 1 || statuses[0].Status != "stale" || statuses[0].ActiveInstances != 0 {
		t.Fatalf("statuses = %+v, want one stale proxy after two missed heartbeat intervals", statuses)
	}
}

func TestEventIngestAndAdminEventQuery(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	now := time.Now().UTC()
	body, err := json.Marshal(ingestEventsRequest{
		Events: []AdminEvent{
			{
				ID:               "denied",
				ObservedAt:       now,
				Type:             "egress.denied",
				Severity:         "warning",
				Message:          "denied request method=GET destination=iana.org:80",
				Count:            5,
				ProxyID:          "10.42.0.17",
				ProxyType:        "http:builtin",
				WorkloadIdentity: codeAgentIdentity,
				WorkloadName:     "code-agent",
				Destination:      &EventDestination{Scheme: "http", Host: "iana.org", Port: 80},
			},
			{
				ID:               "proxy-error",
				ObservedAt:       now.Add(time.Second),
				Type:             "proxy.error",
				Severity:         "error",
				Message:          "proxy error resolving upstream",
				Count:            2,
				ProxyID:          "10.42.0.17",
				ProxyType:        "http:builtin",
				WorkloadIdentity: codeAgentIdentity,
				WorkloadName:     "code-agent",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ingest := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, ingest)
	if response.Code != http.StatusOK {
		t.Fatalf("ingest status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/events?proxy_id=10.42.0.17&limit=1", nil)
	response = httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("query status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var out AdminEventsResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(out.Events))
	}
	got := out.Events[0]
	if got.Type != "proxy.error" || got.ProxyID != "10.42.0.17" || got.WorkloadIdentity != codeAgentIdentity || got.Count != 2 {
		t.Fatalf("event = %+v, want newest proxy error event", got)
	}
	if out.NextCursor == "" {
		t.Fatal("nextCursor is empty, want cursor for second page")
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/admin/events?proxy_id=10.42.0.17&limit=1&cursor="+url.QueryEscape(out.NextCursor), nil)
	response = httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("second page status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var secondPage AdminEventsResponse
	if err := json.NewDecoder(response.Body).Decode(&secondPage); err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Events) != 1 || secondPage.Events[0].Type != "egress.denied" || secondPage.Events[0].Count != 5 {
		t.Fatalf("second page events = %+v, want older denied event", secondPage.Events)
	}
	if secondPage.NextCursor != "" {
		t.Fatalf("second page nextCursor = %q, want empty", secondPage.NextCursor)
	}
}

func TestEventIngestRateLimitsPerProxy(t *testing.T) {
	server := newFixtureServerWithOptions(t, ServerOptions{
		EventIngestRatePerProxy:  1,
		EventIngestBurstPerProxy: 1,
	})
	now := time.Now().UTC()
	body, err := json.Marshal(ingestEventsRequest{
		Events: []AdminEvent{
			{
				ID:               "first",
				ObservedAt:       now,
				Type:             "egress.denied",
				ProxyID:          "10.42.0.17",
				WorkloadIdentity: codeAgentIdentity,
			},
			{
				ID:               "second",
				ObservedAt:       now.Add(time.Millisecond),
				Type:             "proxy.error",
				ProxyID:          "10.42.0.17",
				WorkloadIdentity: codeAgentIdentity,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ingest status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var ingestOut IngestEventsResponse
	if err := json.NewDecoder(response.Body).Decode(&ingestOut); err != nil {
		t.Fatal(err)
	}
	if ingestOut.Stored != 1 || ingestOut.Suppressed != 1 {
		t.Fatalf("ingest = %+v, want one stored and one suppressed", ingestOut)
	}

	query := httptest.NewRequest(http.MethodGet, "/v1/admin/events?proxy_id=10.42.0.17", nil)
	response = httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, query)
	if response.Code != http.StatusOK {
		t.Fatalf("query status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var eventsOut AdminEventsResponse
	if err := json.NewDecoder(response.Body).Decode(&eventsOut); err != nil {
		t.Fatal(err)
	}
	if len(eventsOut.Events) != 1 || len(eventsOut.Suppressed) != 1 || eventsOut.Suppressed[0].Count != 1 {
		t.Fatalf("events response = %+v, want one event and one suppressed count", eventsOut)
	}
}

func TestEventIngestRateLimitsGlobally(t *testing.T) {
	server := newFixtureServerWithOptions(t, ServerOptions{
		EventIngestRate:  1,
		EventIngestBurst: 1,
	})
	now := time.Now().UTC()
	body, err := json.Marshal(ingestEventsRequest{
		Events: []AdminEvent{
			{
				ID:               "first",
				ObservedAt:       now,
				Type:             "egress.denied",
				ProxyID:          "10.42.0.17",
				WorkloadIdentity: codeAgentIdentity,
			},
			{
				ID:               "second",
				ObservedAt:       now.Add(time.Millisecond),
				Type:             "egress.denied",
				ProxyID:          "10.42.0.18",
				WorkloadIdentity: codeAgentIdentity,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ingest status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var ingestOut IngestEventsResponse
	if err := json.NewDecoder(response.Body).Decode(&ingestOut); err != nil {
		t.Fatal(err)
	}
	if ingestOut.Stored != 1 || ingestOut.Suppressed != 1 {
		t.Fatalf("ingest = %+v, want one stored and one globally suppressed", ingestOut)
	}

	query := httptest.NewRequest(http.MethodGet, "/v1/admin/events", nil)
	response = httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, query)
	if response.Code != http.StatusOK {
		t.Fatalf("query status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var eventsOut AdminEventsResponse
	if err := json.NewDecoder(response.Body).Decode(&eventsOut); err != nil {
		t.Fatal(err)
	}
	if len(eventsOut.Events) != 1 || len(eventsOut.Suppressed) != 1 || eventsOut.Suppressed[0].ProxyID != "10.42.0.18" {
		t.Fatalf("events response = %+v, want one stored event and suppressed second proxy", eventsOut)
	}
}

func TestListAdminProxiesDevToken(t *testing.T) {
	server := newFixtureServer(t, "secret-dev-token", nil)
	handler := server.AdminHandler()

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

func TestWorkerAndAdminAuthCanBeSplit(t *testing.T) {
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode: AuthModeSPIFFE,
		AdminAuthMode:  AuthModeDevToken,
		AdminDevToken:  "admin-token",
	})
	workerHandler := server.WorkerHandler()
	adminHandler := server.AdminHandler()

	workerRequest := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	workerRequest.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{CertificateWithSPIFFEID(codeAgentIdentity)},
	}
	workerResponse := httptest.NewRecorder()
	workerHandler.ServeHTTP(workerResponse, workerRequest)
	if workerResponse.Code != http.StatusOK {
		t.Fatalf("worker status = %d, want %d; body = %s", workerResponse.Code, http.StatusOK, workerResponse.Body.String())
	}

	unauthorizedAdmin := httptest.NewRecorder()
	workerHandler.ServeHTTP(unauthorizedAdmin, httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil))
	if unauthorizedAdmin.Code != http.StatusNotFound {
		t.Fatalf("worker admin route status = %d, want %d", unauthorizedAdmin.Code, http.StatusNotFound)
	}

	unauthorizedAdmin = httptest.NewRecorder()
	adminHandler.ServeHTTP(unauthorizedAdmin, httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil))
	if unauthorizedAdmin.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized admin status = %d, want %d", unauthorizedAdmin.Code, http.StatusUnauthorized)
	}

	adminRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	adminRequest.Header.Set("Authorization", "Bearer admin-token")
	adminResponse := httptest.NewRecorder()
	adminHandler.ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want %d; body = %s", adminResponse.Code, http.StatusOK, adminResponse.Body.String())
	}
}

func TestAdminOIDCRBACAllowsMappedViewerGroup(t *testing.T) {
	issuer, jwksURL, sign := newOIDCTestIssuer(t)
	authenticator, err := NewOIDCAuthenticator(context.Background(), OIDCConfig{
		Issuer:   issuer,
		Audience: "airlock-web",
		JWKSURL:  jwksURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode: AuthModeSPIFFE,
		AdminAuthMode:  AuthModeOIDC,
		AdminOIDC:      authenticator,
		AdminRBAC: NewRBACAuthorizer(RBACConfig{RoleBindings: map[string][]string{
			"airlock-viewers": {"viewer"},
		}}),
	})

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	request.Header.Set("Authorization", "Bearer "+sign(map[string]any{
		"email":  "viewer@example.test",
		"groups": []string{"airlock-viewers"},
	}))
	response := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
}

func TestAdminOIDCRBACRejectsTokenWithoutPermission(t *testing.T) {
	issuer, jwksURL, sign := newOIDCTestIssuer(t)
	authenticator, err := NewOIDCAuthenticator(context.Background(), OIDCConfig{
		Issuer:   issuer,
		Audience: "airlock-web",
		JWKSURL:  jwksURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode: AuthModeSPIFFE,
		AdminAuthMode:  AuthModeOIDC,
		AdminOIDC:      authenticator,
		AdminRBAC: NewRBACAuthorizer(RBACConfig{RoleBindings: map[string][]string{
			"airlock-viewers": {"viewer"},
		}}),
	})

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/proxies", nil)
	request.Header.Set("Authorization", "Bearer "+sign(map[string]any{
		"email":  "stranger@example.test",
		"groups": []string{"other"},
	}))
	response := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusForbidden, response.Body.String())
	}
}

func TestLoadPolicyStoreErrorsOnMissingSecretProviderRef(t *testing.T) {
	_, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent-vault.yaml")},
		nil,
	)
	if err == nil {
		t.Fatal("LoadPolicyStoreWithSecretProviderConfigs() error = nil")
	}
	if !strings.Contains(err.Error(), "secretProviderRef airlock-system/default-vault not found") {
		t.Fatalf("error = %q, want missing secret provider ref", err)
	}
}

func TestSecretProviderRefDefaultsToWorkloadNamespace(t *testing.T) {
	workload := policy.AirlockWorkload{
		APIVersion: policy.APIVersion,
		Kind:       "AirlockWorkload",
		Metadata:   policy.Metadata{Name: "code-agent", Namespace: "airlock-prod"},
		Spec: policy.WorkloadSpec{
			SecretProviderRef: policy.SecretProviderRef{Name: "default"},
			Workload: policy.WorkloadIdentity{
				SPIFFEID: "spiffe://airlock.local/ns/prod/sa/code-agent/component/airlock-proxy-worker",
			},
			PolicyRefs: []policy.PolicyRef{{Name: "github"}},
		},
	}
	prod := policy.SecretProviderConfig{
		Metadata: policy.Metadata{Name: "default", Namespace: "airlock-prod"},
		Spec: policy.SecretProviderConfigSpec{
			Vault: policy.VaultProviderSpec{Address: "https://vault.prod.example"},
		},
	}
	dev := prod
	dev.Metadata.Namespace = "airlock-dev"
	dev.Spec.Vault.Address = "https://vault.dev.example"

	resolved, err := resolveSecretProviderConfig(workload, map[string]policy.SecretProviderConfig{
		providerConfigKey(prod.Metadata.Namespace, prod.Metadata.Name): prod,
		providerConfigKey(dev.Metadata.Namespace, dev.Metadata.Name):   dev,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil || resolved.Spec.Vault.Address != "https://vault.prod.example" {
		t.Fatalf("resolved provider = %+v, want airlock-prod/default", resolved)
	}
}

func TestGetPolicySupportsQueryParameter(t *testing.T) {
	server := newFixtureServer(t, "", nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/policies?workload_identity="+url.QueryEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	server.WorkerHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
}

func TestGetPolicyUnknownIdentity(t *testing.T) {
	var audit bytes.Buffer
	server := newFixtureServer(t, "", &audit)
	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape("spiffe://airlock.local/ns/demo/sa/unknown"), nil)
	response := httptest.NewRecorder()

	server.WorkerHandler().ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if !strings.Contains(audit.String(), `"outcome":"not_found"`) {
		t.Fatalf("audit line = %s, want not_found outcome", audit.String())
	}
}

func TestGetPolicyDevToken(t *testing.T) {
	server := newFixtureServer(t, "secret-dev-token", nil)
	handler := server.WorkerHandler()

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
	handler := newFixtureServerWithAuth(t, AuthModeSPIFFE, "", nil).WorkerHandler()

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
	handler := newFixtureServerWithAuth(t, AuthModeSPIFFE, "", nil).WorkerHandler()

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
	handler := newFixtureServerWithAuth(t, AuthModeSPIFFE, "", nil).WorkerHandler()
	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestReadyRequiresPolicy(t *testing.T) {
	server := NewServerWithOptions(&PolicyStore{byWorkload: map[string]policy.CompiledPolicy{}}, ServerOptions{})
	response := httptest.NewRecorder()

	server.HealthHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

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
	opts := ServerOptions{
		WorkerAuthMode:       authMode,
		WorkerDevToken:       devToken,
		AdminAuthMode:        authMode,
		AdminDevToken:        devToken,
		AllowInsecureDevAuth: authMode == AuthModeNone || authMode == AuthModeDevToken,
	}
	if audit != nil {
		opts.Audit = audit
	}
	return newFixtureServerWithOptions(t, opts)
}

func newFixtureServerWithOptions(t *testing.T, opts ServerOptions) *Server {
	t.Helper()

	store, err := LoadPolicyStore(
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Audit == nil {
		opts.Audit = io.Discard
	}
	if !opts.AllowInsecureDevAuth && (isInsecureDevAuth(opts.WorkerAuthMode) || isInsecureDevAuth(opts.AdminAuthMode)) {
		opts.AllowInsecureDevAuth = true
	}
	return NewServerWithOptions(store, opts)
}

func isInsecureDevAuth(mode AuthMode) bool {
	return mode == "" || mode == AuthModeNone || mode == AuthModeDevToken
}

func CertificateWithSPIFFEID(rawID string) *x509.Certificate {
	parsed, err := url.Parse(rawID)
	if err != nil {
		return &x509.Certificate{}
	}
	return &x509.Certificate{URIs: []*url.URL{parsed}}
}

func newOIDCTestIssuer(t *testing.T) (issuer string, jwksURL string, sign func(privateClaims map[string]any) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicJWK := jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     "test-key",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, http.StatusOK, map[string]any{"jwks_uri": issuer + "/keys"})
		case "/keys":
			writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	issuer = server.URL
	jwksURL = server.URL + "/keys"

	return issuer, jwksURL, func(privateClaims map[string]any) string {
		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
		)
		if err != nil {
			t.Fatal(err)
		}
		claims := jwt.Claims{
			Issuer:   issuer,
			Subject:  "subject-1",
			Audience: jwt.Audience{"airlock-web"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		token, err := jwt.Signed(signer).Claims(claims).Claims(privateClaims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
}
