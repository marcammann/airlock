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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/marcammann/airlock/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const codeAgentIdentity = "spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"

func TestGetPolicyReturnsCompiledPolicyAndAuditEvent(t *testing.T) {
	var audit bytes.Buffer
	server := newFixtureServer(t, &audit)

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

func TestGetPolicySupportsETagNotModified(t *testing.T) {
	server := newFixtureServer(t, nil)
	handler := server.WorkerHandler()
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d; body = %s", first.Code, http.StatusOK, first.Body.String())
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("ETag header is empty")
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	request.Header.Set("If-None-Match", etag)
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request)
	if second.Code != http.StatusNotModified {
		t.Fatalf("second status = %d, want %d; body = %s", second.Code, http.StatusNotModified, second.Body.String())
	}
	if second.Body.Len() != 0 {
		t.Fatalf("second body = %q, want empty", second.Body.String())
	}
}

func TestPolicyFetchRateLimited(t *testing.T) {
	restore := overrideRequestRateLimits()
	defer restore()
	policyFetchRateLimit = requestRateLimit{RatePerSecond: 1, Burst: 1}
	server := newFixtureServer(t, nil)
	handler := server.WorkerHandler()

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d; body = %s", first.Code, http.StatusOK, first.Body.String())
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d; body = %s", second.Code, http.StatusTooManyRequests, second.Body.String())
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header is empty")
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
		WorkerAuthMode: AuthModeNone,
		AdminAuthMode:  AuthModeNone,
		Insecure:       true,
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
		WorkerAuthMode: AuthModeNone,
		AdminAuthMode:  AuthModeNone,
		Insecure:       true,
		Audit:          &audit,
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
	server := newFixtureServer(t, nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	response := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(response, request)

	body := response.Body.String()
	require.Equal(t, http.StatusOK, response.Code, "body = %s", body)

	var out AdminWorkloadsResponse
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Len(t, out.Workloads, 1)

	got := out.Workloads[0]
	assert.Equal(t, "code-agent", got.Name)
	require.Len(t, got.PolicyRefs, 1)
	assert.Equal(t, "openai-api", got.PolicyRefs[0].Name)
	assert.Equal(t, codeAgentIdentity, got.Workload.SPIFFEID)
	assert.Equal(t, 1, got.EgressCount)
	assert.Equal(t, 1, got.RewriteCount)
	require.Len(t, got.Egress, 1)
	assert.Equal(t, "api.example.test", got.Egress[0].Host)
	assert.NotContains(t, body, "AIRLOCK_TEST_TOKEN")
	assert.NotContains(t, body, "Bearer {{secret}}")
	assert.NotContains(t, body, "Authorization")
}

func TestListAdminPoliciesReturnsReusablePolicySummaries(t *testing.T) {
	server := newFixtureServer(t, nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/policies", nil)
	response := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(response, request)

	body := response.Body.String()
	require.Equal(t, http.StatusOK, response.Code, "body = %s", body)

	var out AdminPoliciesResponse
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Len(t, out.Policies, 1)

	got := out.Policies[0]
	assert.Equal(t, "openai-api", got.Name)
	assert.Equal(t, "airlock-system", got.Namespace)
	assert.Equal(t, 1, got.EgressCount)
	assert.Equal(t, 1, got.RewriteCount)
	require.Len(t, got.Egress, 1)
	assert.Equal(t, "api.example.test", got.Egress[0].Host)
	assert.NotContains(t, body, "AIRLOCK_TEST_TOKEN")
	assert.NotContains(t, body, "Bearer {{secret}}")
	assert.NotContains(t, body, "Authorization")
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
	server := newFixtureServer(t, nil)
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
	require.NoError(t, err)
	heartbeat := httptest.NewRequest(http.MethodPost, "/v1/proxies/heartbeat", bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, heartbeat)
	require.Equal(t, http.StatusOK, response.Code, "body = %s", response.Body.String())

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	response = httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code, "body = %s", response.Body.String())
	var out AdminWorkloadsResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&out))
	require.Len(t, out.Workloads, 1)

	got := out.Workloads[0]
	assert.Equal(t, 1, got.InstanceCount)
	assert.Equal(t, 1, got.ActiveInstances)
	assert.Equal(t, "active", got.Status)
	require.Len(t, got.Instances, 1)
	assert.Equal(t, "10.42.0.17", got.Instances[0].ID)
	assert.Equal(t, DecisionCounts{Allowed: 2, Denied: 1}, got.Decisions)
}

func TestListAdminWorkloadsIncludesRecentAlerts(t *testing.T) {
	server := newFixtureServer(t, nil)
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

	require.Equal(t, http.StatusOK, response.Code, "body = %s", response.Body.String())
	var out AdminWorkloadsResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&out))
	require.Len(t, out.Workloads, 1)

	got := out.Workloads[0].Alerts
	assert.Equal(t, AlertCounts{Denied: 3, ProxyError: 2, Total: 5}, got)
}

func TestListAdminProxiesReturnsGroupedHeartbeatInventory(t *testing.T) {
	server := newFixtureServer(t, nil)
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
	require.NoError(t, err)
	heartbeat := httptest.NewRequest(http.MethodPost, "/v1/proxies/heartbeat", bytes.NewReader(firstBody))
	response := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, heartbeat)
	require.Equal(t, http.StatusOK, response.Code, "body = %s", response.Body.String())
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
	require.NoError(t, err)
	heartbeat = httptest.NewRequest(http.MethodPost, "/v1/proxies/heartbeat", bytes.NewReader(secondBody))
	response = httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(response, heartbeat)
	require.Equal(t, http.StatusOK, response.Code, "body = %s", response.Body.String())

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/proxies", nil)
	response = httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code, "body = %s", response.Body.String())
	var out AdminProxiesResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&out))
	assert.Equal(t, "control-plane-heartbeat", out.Source)
	require.Len(t, out.Proxies, 1)

	got := out.Proxies[0]
	assert.Equal(t, codeAgentIdentity, got.WorkloadIdentity)
	assert.Equal(t, "code-agent", got.WorkloadName)
	assert.Equal(t, "active", got.Status)
	assert.Equal(t, 2, got.InstanceCount)
	assert.Equal(t, 2, got.ActiveInstances)
	require.Len(t, got.Instances, 2)
	assert.Equal(t, DecisionCounts{Allowed: 5, Denied: 5}, got.Decisions)
	assert.Equal(t, "proxy-1", got.Instances[0].ID)
	assert.Equal(t, "proxy-2", got.Instances[1].ID)
}

func TestProxyHeartbeatRejectsMissingHeartbeatInterval(t *testing.T) {
	server := newFixtureServer(t, nil)
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

func TestStaleProxiesArePruned(t *testing.T) {
	server := newFixtureServerWithOptions(t, ServerOptions{HeartbeatStaleThreshold: 2})
	now := time.Now().UTC()
	server.mu.Lock()
	server.proxies["stale"] = proxyRecord{
		ProxyHeartbeatRequest: ProxyHeartbeatRequest{
			ID:                "stale",
			WorkloadIdentity:  codeAgentIdentity,
			WorkloadName:      "code-agent",
			ProxyType:         "http:builtin",
			HeartbeatInterval: "10s",
		},
		LastHeartbeatAt: now.Add(-41 * time.Second),
	}
	server.proxies["active"] = proxyRecord{
		ProxyHeartbeatRequest: ProxyHeartbeatRequest{
			ID:                "active",
			WorkloadIdentity:  codeAgentIdentity,
			WorkloadName:      "code-agent",
			ProxyType:         "http:builtin",
			HeartbeatInterval: "10s",
		},
		LastHeartbeatAt: now.Add(-10 * time.Second),
	}
	server.eventIngestBuckets["stale"] = eventIngestBucket{Tokens: 1, Last: now}
	server.eventIngestBuckets["active"] = eventIngestBucket{Tokens: 1, Last: now}
	server.eventSuppressed["stale"] = 3
	server.mu.Unlock()

	server.pruneRuntimeState(now)

	server.mu.RLock()
	defer server.mu.RUnlock()
	if _, ok := server.proxies["stale"]; ok {
		t.Fatal("stale proxy was not pruned")
	}
	if _, ok := server.proxies["active"]; !ok {
		t.Fatal("active proxy was pruned")
	}
	if _, ok := server.eventIngestBuckets["stale"]; ok {
		t.Fatal("stale proxy event bucket was not pruned")
	}
	if _, ok := server.eventIngestBuckets["active"]; !ok {
		t.Fatal("active proxy event bucket was pruned")
	}
	if len(server.eventSuppressed) != 0 {
		t.Fatalf("eventSuppressed = %+v, want counters decayed to zero", server.eventSuppressed)
	}
}

func TestStaleProxiesRemainVisibleBeforePruneWindow(t *testing.T) {
	server := newFixtureServerWithOptions(t, ServerOptions{HeartbeatStaleThreshold: 2})
	now := time.Now().UTC()
	server.mu.Lock()
	server.proxies["stale-visible"] = proxyRecord{
		ProxyHeartbeatRequest: ProxyHeartbeatRequest{
			ID:                "stale-visible",
			WorkloadIdentity:  codeAgentIdentity,
			WorkloadName:      "code-agent",
			ProxyType:         "http:builtin",
			HeartbeatInterval: "10s",
		},
		LastHeartbeatAt: now.Add(-21 * time.Second),
	}
	server.mu.Unlock()

	server.pruneRuntimeState(now)

	statuses := server.proxyStatuses(now)
	if len(statuses) != 1 || statuses[0].Status != "stale" {
		t.Fatalf("statuses = %+v, want stale proxy retained before prune window", statuses)
	}
}

func TestEventIngestAndAdminEventQuery(t *testing.T) {
	server := newFixtureServer(t, nil)
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

func TestWorkerAndAdminAuthCanBeSplit(t *testing.T) {
	adminAuth, err := NewAPIKeyAuthenticator("local-admin", []APIKey{{ID: "console", Value: "admin-token"}})
	if err != nil {
		t.Fatal(err)
	}
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode:     AuthModeSPIFFE,
		AdminAuthenticator: NewAuthenticatorChain([]RequestAuthenticator{adminAuth}),
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

func TestSPIFFEAdminWithoutRBACBindingsDenies(t *testing.T) {
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode: AuthModeSPIFFE,
		AdminAuthMode:  AuthModeSPIFFE,
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{CertificateWithSPIFFEID("spiffe://airlock.local/ns/demo/sa/admin")},
	}
	response := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusForbidden, response.Body.String())
	}
}

func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	adminAuth, err := NewAPIKeyAuthenticator("local-admin", []APIKey{{ID: "console", Value: "admin-token"}})
	if err != nil {
		t.Fatal(err)
	}
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode:     AuthModeSPIFFE,
		AdminAuthenticator: NewAuthenticatorChain([]RequestAuthenticator{adminAuth}),
	})
	for _, scheme := range []string{"bearer", "BEARER", "Bearer"} {
		t.Run(scheme, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
			request.Header.Set("Authorization", scheme+" admin-token")
			response := httptest.NewRecorder()

			server.AdminHandler().ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
			}
		})
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

func TestOIDCAuthenticatorEnforcesRequiredClaims(t *testing.T) {
	issuer, jwksURL, sign := newOIDCTestIssuer(t)
	authenticator, err := NewOIDCAuthenticator(context.Background(), OIDCConfig{
		Issuer:   issuer,
		Audience: "airlock-web",
		JWKSURL:  jwksURL,
		RequiredClaims: map[string]string{
			"repository": "marcammann/airlock",
			"ref":        "refs/heads/main",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := authenticator.Authenticate(context.Background(), sign(map[string]any{
		"repository": "marcammann/airlock",
		"ref":        "refs/heads/main",
	})); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if _, err := authenticator.Authenticate(context.Background(), sign(map[string]any{
		"repository": "marcammann/airlock",
		"ref":        "refs/heads/dev",
	})); err == nil {
		t.Fatal("Authenticate() error = nil, want required claim failure")
	}
}

func TestOIDCAuthenticatorRejectsWrongAudience(t *testing.T) {
	assertOIDCRejectsWrongAudience(t)
}

func TestOIDCRejectsWrongAudience(t *testing.T) {
	assertOIDCRejectsWrongAudience(t)
}

func assertOIDCRejectsWrongAudience(t *testing.T) {
	t.Helper()
	issuer, jwksURL, sign := newOIDCTestIssuer(t)
	authenticator, err := NewOIDCAuthenticator(context.Background(), OIDCConfig{
		Issuer:   issuer,
		Audience: "airlock-web",
		JWKSURL:  jwksURL,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = authenticator.Authenticate(context.Background(), sign(map[string]any{
		"aud": "other-app",
	}))
	if err == nil {
		t.Fatal("Authenticate() error = nil, want audience failure")
	}
}

func TestOIDCAuthenticatorRefreshesJWKSOnKeyRotation(t *testing.T) {
	assertOIDCRefreshesJWKSOnKeyRotation(t)
}

func TestOIDCRefreshesJWKSOnKeyRotation(t *testing.T) {
	assertOIDCRefreshesJWKSOnKeyRotation(t)
}

func assertOIDCRefreshesJWKSOnKeyRotation(t *testing.T) {
	t.Helper()
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	currentJWK := oidcTestPublicJWK("test-key-1", &key1.PublicKey)
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, http.StatusOK, map[string]any{"jwks_uri": issuer + "/keys"})
		case "/keys":
			mu.Lock()
			key := currentJWK
			mu.Unlock()
			writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	issuer = server.URL

	authenticator, err := NewOIDCAuthenticator(context.Background(), OIDCConfig{
		Issuer:   issuer,
		Audience: "airlock-web",
		JWKSURL:  issuer + "/keys",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(context.Background(), signOIDCTestToken(t, key1, "test-key-1", issuer, "airlock-web", nil)); err != nil {
		t.Fatalf("Authenticate(first token) error = %v", err)
	}

	mu.Lock()
	currentJWK = oidcTestPublicJWK("test-key-2", &key2.PublicKey)
	mu.Unlock()

	if _, err := authenticator.Authenticate(context.Background(), signOIDCTestToken(t, key2, "test-key-2", issuer, "airlock-web", nil)); err != nil {
		t.Fatalf("Authenticate(rotated token) error = %v", err)
	}
}

func TestAdminAuthConfigAPIKeyRBACAllowsViewer(t *testing.T) {
	configPath := writeAuthConfig(t, `
version: airlock.dev/v1alpha1
auth:
  admin:
    providers:
      - name: local-admin
        type: apiKey
        keys:
          - id: console
            value: admin-secret
    rbac:
      roleBindings:
        - subject: key:console
          roles: [viewer]
      roles:
        viewer:
          permissions:
            - policy:read
            - workload:read
            - proxy:read
`)
	runtimeAuth, err := LoadRuntimeAuthConfig(context.Background(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode:     AuthModeSPIFFE,
		AdminAuthenticator: runtimeAuth.AdminAuthenticator,
		AdminRBAC:          runtimeAuth.AdminRBAC,
	})

	unauthorized := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/workloads", nil)
	request.Header.Set("Authorization", "Bearer admin-secret")
	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
}

func TestEnrollmentConfigMintsAndRedeemsOneTimeToken(t *testing.T) {
	configPath := writeAuthConfig(t, `
version: airlock.dev/v1alpha1
auth:
  enrollment:
    defaultTTL: 2m
    maxTTL: 10m
    providers:
      - name: local-dispatchers
        type: apiKey
        keys:
          - id: daytona
            value: dispatcher-secret
    grants:
      - subject: key:daytona
        permissions: [enrollment:create]
        workloads:
          - namespace: airlock-system
            name: code-agent
`)
	runtimeAuth, err := LoadRuntimeAuthConfig(context.Background(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode:          AuthModeSPIFFE,
		AdminAuthMode:           AuthModeSPIFFE,
		EnrollmentAuthenticator: runtimeAuth.EnrollmentAuthenticator,
		EnrollmentAuthorizer:    runtimeAuth.EnrollmentAuthorizer,
		EnrollmentDefaultTTL:    runtimeAuth.EnrollmentDefaultTTL,
		EnrollmentMaxTTL:        runtimeAuth.EnrollmentMaxTTL,
	})

	createBody := strings.NewReader(`{"workload":{"namespace":"airlock-system","name":"code-agent"},"ttlSeconds":120}`)
	createRequest := httptest.NewRequest(http.MethodPost, "/v1/enrollments", createBody)
	createRequest.Header.Set("Authorization", "Bearer dispatcher-secret")
	createResponse := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body = %s", createResponse.Code, http.StatusCreated, createResponse.Body.String())
	}
	var created CreateEnrollmentResponse
	if err := json.NewDecoder(createResponse.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, "al_enroll_") {
		t.Fatalf("token = %q, want al_enroll_ prefix", created.Token)
	}
	if created.WorkloadIdentity != codeAgentIdentity {
		t.Fatalf("workloadIdentity = %q, want %q", created.WorkloadIdentity, codeAgentIdentity)
	}

	redeemRequest := httptest.NewRequest(http.MethodPost, "/v1/enrollments/redeem", nil)
	redeemRequest.Header.Set("Authorization", "Bearer "+created.Token)
	redeemResponse := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(redeemResponse, redeemRequest)
	if redeemResponse.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, want %d; body = %s", redeemResponse.Code, http.StatusOK, redeemResponse.Body.String())
	}
	var redeemed RedeemEnrollmentResponse
	if err := json.NewDecoder(redeemResponse.Body).Decode(&redeemed); err != nil {
		t.Fatal(err)
	}
	if redeemed.Policy.Workload.SPIFFEID != codeAgentIdentity {
		t.Fatalf("redeemed spiffeId = %q, want %q", redeemed.Policy.Workload.SPIFFEID, codeAgentIdentity)
	}

	secondRedeem := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(secondRedeem, redeemRequest)
	if secondRedeem.Code != http.StatusUnauthorized {
		t.Fatalf("second redeem status = %d, want %d", secondRedeem.Code, http.StatusUnauthorized)
	}

	legacyRequest := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollments", strings.NewReader(`{}`))
	legacyRequest.Header.Set("Authorization", "Bearer dispatcher-secret")
	legacyResponse := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(legacyResponse, legacyRequest)
	if legacyResponse.Code != http.StatusNotFound {
		t.Fatalf("legacy create status = %d, want %d", legacyResponse.Code, http.StatusNotFound)
	}

	adminCreateRequest := httptest.NewRequest(http.MethodPost, "/v1/enrollments", strings.NewReader(`{}`))
	adminCreateRequest.Header.Set("Authorization", "Bearer dispatcher-secret")
	adminCreateResponse := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(adminCreateResponse, adminCreateRequest)
	if adminCreateResponse.Code != http.StatusNotFound {
		t.Fatalf("admin create status = %d, want %d", adminCreateResponse.Code, http.StatusNotFound)
	}

	adminRedeemRequest := httptest.NewRequest(http.MethodPost, "/v1/enrollments/redeem", nil)
	adminRedeemRequest.Header.Set("Authorization", "Bearer "+created.Token)
	adminRedeemResponse := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(adminRedeemResponse, adminRedeemRequest)
	if adminRedeemResponse.Code != http.StatusNotFound {
		t.Fatalf("admin redeem status = %d, want %d", adminRedeemResponse.Code, http.StatusNotFound)
	}
}

func TestEnrollmentCreateRateLimited(t *testing.T) {
	restore := overrideRequestRateLimits()
	defer restore()
	enrollmentCreateRateLimit = requestRateLimit{RatePerSecond: 1, Burst: 1}
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode: AuthModeNone,
		AdminAuthMode:  AuthModeNone,
		Insecure:       true,
	})
	handler := server.WorkerHandler()
	body := `{"workload":{"namespace":"airlock-system","name":"code-agent"}}`

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/v1/enrollments", strings.NewReader(body)))
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, want %d; body = %s", first.Code, http.StatusCreated, first.Body.String())
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/v1/enrollments", strings.NewReader(body)))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d; body = %s", second.Code, http.StatusTooManyRequests, second.Body.String())
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header is empty")
	}
}

func TestEnrollmentSweeperDeletesExpiredTokens(t *testing.T) {
	store := NewEnrollmentStore(EnrollmentStoreOptions{
		DefaultTTL: 10 * time.Millisecond,
		MaxTTL:     time.Second,
	})
	_, _, err := store.Mint(policy.CompiledPolicy{
		Version:    policy.APIVersion,
		PolicyName: "code-agent",
		Workload:   policy.WorkloadIdentity{SPIFFEID: codeAgentIdentity},
	}, 10*time.Millisecond, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go store.RunSweeper(ctx, 5*time.Millisecond)

	deadline := time.After(500 * time.Millisecond)
	for {
		if store.Count() == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for enrollment sweeper")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestEnrollmentWithoutAuthorizerDenies(t *testing.T) {
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode: AuthModeSPIFFE,
		AdminAuthMode:  AuthModeSPIFFE,
	})
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/enrollments",
		strings.NewReader(`{"workload":{"namespace":"airlock-system","name":"code-agent"}}`),
	)
	response := httptest.NewRecorder()

	server.WorkerHandler().ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusForbidden, response.Body.String())
	}
}

func TestEnrollmentConfigAllowsOIDCDispatcher(t *testing.T) {
	issuer, jwksURL, sign := newOIDCTestIssuer(t)
	config := strings.ReplaceAll(`
version: airlock.dev/v1alpha1
auth:
  enrollment:
    providers:
      - name: compose-oidc
        type: oidc
        issuer: ISSUER
        audience: airlock-web
        jwksUrl: JWKS_URL
        requiredClaims:
          token_use: enrollment
    grants:
      - subject: provider:compose-oidc:sub:subject-1
        permissions: [enrollment:create]
        workloads:
          - namespace: airlock-system
            name: code-agent
`, "ISSUER", issuer)
	config = strings.ReplaceAll(config, "JWKS_URL", jwksURL)
	configPath := writeAuthConfig(t, config)

	runtimeAuth, err := LoadRuntimeAuthConfig(context.Background(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode:          AuthModeSPIFFE,
		AdminAuthMode:           AuthModeSPIFFE,
		EnrollmentAuthenticator: runtimeAuth.EnrollmentAuthenticator,
		EnrollmentAuthorizer:    runtimeAuth.EnrollmentAuthorizer,
	})

	createBody := strings.NewReader(`{"workload":{"namespace":"airlock-system","name":"code-agent"}}`)
	createRequest := httptest.NewRequest(http.MethodPost, "/v1/enrollments", createBody)
	createRequest.Header.Set("Authorization", "Bearer "+sign(map[string]any{"token_use": "enrollment"}))
	createResponse := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body = %s", createResponse.Code, http.StatusCreated, createResponse.Body.String())
	}
}

func TestEnrollmentConfigRejectsUnauthorizedWorkload(t *testing.T) {
	configPath := writeAuthConfig(t, `
version: airlock.dev/v1alpha1
auth:
  enrollment:
    providers:
      - name: local-dispatchers
        type: apiKey
        keys:
          - id: daytona
            value: dispatcher-secret
    grants:
      - subject: key:daytona
        permissions: [enrollment:create]
        workloads:
          - namespace: other
            name: code-agent
`)
	runtimeAuth, err := LoadRuntimeAuthConfig(context.Background(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	server := newFixtureServerWithOptions(t, ServerOptions{
		WorkerAuthMode:          AuthModeSPIFFE,
		AdminAuthMode:           AuthModeSPIFFE,
		EnrollmentAuthenticator: runtimeAuth.EnrollmentAuthenticator,
		EnrollmentAuthorizer:    runtimeAuth.EnrollmentAuthorizer,
	})

	createBody := strings.NewReader(`{"workload":{"namespace":"airlock-system","name":"code-agent"}}`)
	createRequest := httptest.NewRequest(http.MethodPost, "/v1/enrollments", createBody)
	createRequest.Header.Set("Authorization", "Bearer dispatcher-secret")
	createResponse := httptest.NewRecorder()
	server.WorkerHandler().ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", createResponse.Code, http.StatusForbidden, createResponse.Body.String())
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

func TestLoadPoliciesValidatesUnreferencedPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-policy.yaml")
	if err := os.WriteFile(path, []byte(`
apiVersion: airlock.dev/v1alpha1
kind: AirlockPolicy
metadata:
  name: invalid
  namespace: airlock-system
spec:
  egress:
    - name: missing-host
      scheme: http
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadPolicies([]string{path})
	if err == nil {
		t.Fatal("loadPolicies() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "host is required") {
		t.Fatalf("error = %q, want host validation", err)
	}
}

func TestSecretProviderRefDefaultsToWorkloadNamespace(t *testing.T) {
	workload := policy.AirlockWorkload{
		TypeMeta: metav1.TypeMeta{
			APIVersion: policy.APIVersion,
			Kind:       "AirlockWorkload",
		},
		Metadata: policy.Metadata{Name: "code-agent", Namespace: "airlock-prod"},
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
	server := newFixtureServer(t, nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/policies?workload_identity="+url.QueryEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	server.WorkerHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
}

func TestGetPolicyUnknownIdentity(t *testing.T) {
	var audit bytes.Buffer
	server := newFixtureServer(t, &audit)
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

func TestGetPolicySPIFFEAuthRequiresMatchingIdentity(t *testing.T) {
	handler := newFixtureServerWithAuth(t, AuthModeSPIFFE, nil).WorkerHandler()

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
	handler := newFixtureServerWithAuth(t, AuthModeSPIFFE, nil).WorkerHandler()

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
	handler := newFixtureServerWithAuth(t, AuthModeSPIFFE, nil).WorkerHandler()
	request := httptest.NewRequest(http.MethodGet, "/v1/policies/"+url.PathEscape(codeAgentIdentity), nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestReadyRequiresPolicy(t *testing.T) {
	store, err := NewPolicyStoreFromCompiled(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServerWithOptions(store, ServerOptions{})
	response := httptest.NewRecorder()

	server.HealthHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func newFixtureServer(t *testing.T, audit *bytes.Buffer) *Server {
	return newFixtureServerWithAuth(t, AuthModeNone, audit)
}

func newFixtureServerWithAuth(t *testing.T, authMode AuthMode, audit *bytes.Buffer) *Server {
	t.Helper()
	opts := ServerOptions{
		WorkerAuthMode: authMode,
		AdminAuthMode:  authMode,
		Insecure:       authMode == AuthModeNone || authMode == "",
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
	if !opts.Insecure && (isInsecureAuth(opts.WorkerAuthMode) || isInsecureAuth(opts.AdminAuthMode)) {
		opts.Insecure = true
	}
	return NewServerWithOptions(store, opts)
}

func writeAuthConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func isInsecureAuth(mode AuthMode) bool {
	return mode == "" || mode == AuthModeNone
}

func overrideRequestRateLimits() func() {
	originalPolicyFetch := policyFetchRateLimit
	originalHeartbeat := heartbeatRateLimit
	originalEnrollmentCreate := enrollmentCreateRateLimit
	originalEnrollmentRedeem := enrollmentRedeemRateLimit
	originalAdminRead := adminReadRateLimit
	return func() {
		policyFetchRateLimit = originalPolicyFetch
		heartbeatRateLimit = originalHeartbeat
		enrollmentCreateRateLimit = originalEnrollmentCreate
		enrollmentRedeemRateLimit = originalEnrollmentRedeem
		adminReadRateLimit = originalAdminRead
	}
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
	publicJWK := oidcTestPublicJWK("test-key", &key.PublicKey)
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
		return signOIDCTestToken(t, key, "test-key", issuer, "airlock-web", privateClaims)
	}
}

func oidcTestPublicJWK(keyID string, publicKey *rsa.PublicKey) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       publicKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
}

func signOIDCTestToken(t *testing.T, key *rsa.PrivateKey, keyID string, issuer string, audience string, privateClaims map[string]any) string {
	t.Helper()
	claims := jwtv5.MapClaims{
		"iss": issuer,
		"sub": "subject-1",
		"aud": []string{audience},
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for name, value := range privateClaims {
		claims[name] = value
	}
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = "JWT"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestReplaceStoreConcurrentReads(t *testing.T) {
	server := newFixtureServerWithAuth(t, AuthModeNone, nil)

	store2, err := LoadPolicyStore(
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					request := httptest.NewRequest(http.MethodGet, "/v1/admin/policies", nil)
					response := httptest.NewRecorder()
					server.AdminHandler().ServeHTTP(response, request)
					if response.Code != http.StatusOK {
						t.Errorf("status = %d, want %d", response.Code, http.StatusOK)
						return
					}
				}
			}
		}()
	}

	for i := 0; i < 100; i++ {
		server.ReplaceStore(store2)
	}

	close(stop)
	wg.Wait()
}
