package worker

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testWorkloadIdentity = "spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"

type staticSecretProvider struct {
	value string
}

func (p staticSecretProvider) Resolve(SecretRef) (string, error) {
	return p.value, nil
}

func testPolicy(host string, port uint16) CompiledPolicy {
	return testPolicyWithScheme("http", host, port)
}

func testPolicyWithScheme(scheme, host string, port uint16) CompiledPolicy {
	return CompiledPolicy{
		Version:    "airlock.dev/v1alpha1",
		PolicyName: "test-policy",
		Workload: WorkloadIdentity{
			SPIFFEID:       testWorkloadIdentity,
			Namespace:      "demo",
			ServiceAccount: "code-agent",
		},
		Egress: []EgressRule{{
			Name:   "local-upstream",
			Scheme: scheme,
			Host:   host,
			Port:   uint32(port),
			Rewrites: []RewriteRule{{
				Target:        "header",
				Name:          "Authorization",
				ValueTemplate: "Bearer {{secret}}",
				ValueFrom: SecretRef{
					Provider: "env",
					Name:     "test-token",
					Env:      "AIRLOCK_TEST_TOKEN",
				},
			}},
		}},
	}
}

func TestAllowedRequestIsForwardedWithRewrittenHeaderAndRedactedLogs(t *testing.T) {
	upstreamAddr, upstreamRequests := startUpstream(t)
	log := NewMemoryEventLog()
	proxy := NewProxyServer(testPolicy("127.0.0.1", uint16(upstreamAddr.Port)), staticSecretProvider{value: "test-token"}, log)
	proxyAddr := startProxy(t, proxy)

	response := sendProxyRequest(t, proxyAddr, fmt.Sprintf(
		"GET http://127.0.0.1:%d/v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n",
		upstreamAddr.Port,
		upstreamAddr.Port,
	))
	upstreamRequest := recvString(t, upstreamRequests)
	logs := strings.Join(log.Entries(), "\n")

	if !strings.HasPrefix(response, "HTTP/1.1 200 OK") {
		t.Fatalf("response = %q, want 200", response)
	}
	if !strings.Contains(upstreamRequest, "GET /v1/models HTTP/1.1") {
		t.Fatalf("upstream request = %q, want origin-form path", upstreamRequest)
	}
	if !strings.Contains(upstreamRequest, "Authorization: Bearer test-token") {
		t.Fatalf("upstream request = %q, want rewritten Authorization", upstreamRequest)
	}
	if strings.Contains(logs, "test-token") {
		t.Fatalf("logs leaked secret: %s", logs)
	}
	if !strings.Contains(logs, Redacted) {
		t.Fatalf("logs = %q, want redacted marker", logs)
	}
}

func TestDeniedRequestFailsClosedBeforeConnectingUpstream(t *testing.T) {
	log := NewMemoryEventLog()
	proxy := NewProxyServer(testPolicy("allowed.test", 80), staticSecretProvider{value: "test-token"}, log)
	proxyAddr := startProxy(t, proxy)

	response := sendProxyRequest(t, proxyAddr, "GET http://denied.test/resource HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n")

	if !strings.HasPrefix(response, "HTTP/1.1 403 Forbidden") {
		t.Fatalf("response = %q, want 403", response)
	}
	if !strings.Contains(strings.Join(log.Entries(), "\n"), "denied request") {
		t.Fatalf("logs = %q, want denied request", log.Entries())
	}
}

func TestEventLogSnapshotCountsDecisions(t *testing.T) {
	log := NewMemoryEventLog()

	log.Record("allowed request method=GET upstream=https://allowed.test path=/v1")
	log.Record("denied request method=GET upstream=https://denied.test reason=no_matching_egress")
	log.Record("denied request method=GET upstream=https://secret.test dependency=secret reason=missing")

	snapshot := log.Snapshot()
	if snapshot.Allowed != 1 || snapshot.Denied != 1 || snapshot.ProxyError != 1 {
		t.Fatalf("snapshot = %+v, want allowed=1 denied=1 proxyError=1", snapshot)
	}
	if snapshot.LastDecisionAt == nil {
		t.Fatal("LastDecisionAt is nil, want decision timestamp")
	}
	if len(snapshot.DecisionEvents) != 3 {
		t.Fatalf("DecisionEvents = %d, want 3", len(snapshot.DecisionEvents))
	}
	if snapshot.DecisionEvents[0].Decision != "allowed" ||
		snapshot.DecisionEvents[1].Decision != "denied" ||
		snapshot.DecisionEvents[2].Decision != "proxy_error" {
		t.Fatalf("DecisionEvents = %+v, want allowed/denied/proxy_error", snapshot.DecisionEvents)
	}
}

func TestHeartbeatReporterPostsProxyStatus(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "demo")
	t.Setenv("POD_NAME", "code-agent-123")
	log := NewMemoryEventLog()
	log.Record("allowed request method=GET upstream=https://github.com path=/owner/repo.git")
	policyFetchedAt := time.Now().UTC()
	processStartedAt := policyFetchedAt.Add(-time.Minute)
	received := make(chan proxyHeartbeatPayload, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/proxies/heartbeat" {
			t.Errorf("request = %s %s, want POST /v1/proxies/heartbeat", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer dev-token" {
			t.Errorf("Authorization = %q, want bearer dev-token", got)
		}
		var payload proxyHeartbeatPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode heartbeat: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	reporter, err := NewHeartbeatReporter(HeartbeatReporterOptions{
		BaseURL:           server.URL,
		DevToken:          "dev-token",
		ProxyID:           "proxy-1",
		ProxyType:         "http:builtin",
		WorkloadIdentity:  testWorkloadIdentity,
		WorkloadName:      "test-policy",
		EffectiveVersion:  "airlock.dev/v1alpha1",
		PolicyFetchedAt:   &policyFetchedAt,
		HeartbeatInterval: 10 * time.Second,
		ProcessStartedAt:  processStartedAt,
		Log:               log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Report(context.Background()); err != nil {
		t.Fatal(err)
	}

	var payload proxyHeartbeatPayload
	select {
	case payload = <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for heartbeat")
	}
	if payload.ID != "proxy-1" || payload.WorkloadIdentity != testWorkloadIdentity || payload.ProxyType != "http:builtin" {
		t.Fatalf("payload identity = %+v, want proxy-1 test identity http:builtin", payload)
	}
	if payload.WorkloadName != "test-policy" || payload.EffectiveVersion != "airlock.dev/v1alpha1" {
		t.Fatalf("payload workload = %+v, want test-policy airlock.dev/v1alpha1", payload)
	}
	if payload.PodNamespace != "demo" || payload.PodName != "code-agent-123" {
		t.Fatalf("pod = %s/%s, want demo/code-agent-123", payload.PodNamespace, payload.PodName)
	}
	if !payload.PolicyFetched || payload.LastPolicyFetchAt == nil || payload.ProcessStartedAt == nil || payload.LastDecisionAt == nil {
		t.Fatalf("payload timestamps = %+v, want policy/process/decision timestamps", payload)
	}
	if payload.HeartbeatInterval != "10s" {
		t.Fatalf("heartbeatInterval = %q, want 10s", payload.HeartbeatInterval)
	}
	if payload.Decisions.Allowed != 1 || payload.Decisions.Denied != 0 || payload.Decisions.ProxyError != 0 {
		t.Fatalf("decisions = %+v, want one allowed decision", payload.Decisions)
	}
}

func TestHeartbeatReporterRunsOnInterval(t *testing.T) {
	requests := make(chan struct{}, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	reporter, err := NewHeartbeatReporter(HeartbeatReporterOptions{
		BaseURL:           server.URL,
		ProxyID:           "proxy-1",
		ProxyType:         "http:builtin",
		WorkloadIdentity:  testWorkloadIdentity,
		WorkloadName:      "test-policy",
		EffectiveVersion:  "airlock.dev/v1alpha1",
		HeartbeatInterval: 20 * time.Millisecond,
		Log:               NewMemoryEventLog(),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reporter.Run(ctx)

	for i := 0; i < 3; i++ {
		select {
		case <-requests:
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timed out waiting for heartbeat %d", i+1)
		}
	}
}

func TestEventReporterPostsAggregatedDeniedEvent(t *testing.T) {
	received := make(chan eventReportPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/events" {
			t.Errorf("request = %s %s, want POST /v1/events", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer dev-token" {
			t.Errorf("Authorization = %q, want bearer dev-token", got)
		}
		var payload eventReportPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode event payload: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	reporter, err := NewEventReporter(EventReporterOptions{
		Endpoint:          server.URL + "/v1/events",
		DevToken:          "dev-token",
		ProxyID:           "10.42.0.17",
		ProxyType:         "http:builtin",
		WorkloadIdentity:  testWorkloadIdentity,
		WorkloadName:      "test-workload",
		WorkloadNamespace: "airlock-system",
		EffectiveVersion:  "airlock.dev/v1alpha1",
		RatePerSecond:     10,
		Burst:             10,
		SourcePolicyByRule: map[string]PolicyRef{
			"example": {Name: "source-policy", Namespace: "airlock-system"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := DecisionEvent{
		ID:       7,
		At:       time.Now().UTC(),
		Decision: "denied",
		Message:  "denied request policy=test-policy policy_version=airlock.dev/v1alpha1 rule=example method=GET destination=example.com:80",
	}
	reporter.RecordDecision(event)
	event.ID = 8
	reporter.RecordDecision(event)
	if err := reporter.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	var payload eventReportPayload
	select {
	case payload = <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event report")
	}
	if len(payload.Events) != 1 {
		t.Fatalf("events = %+v, want one aggregated event", payload.Events)
	}
	got := payload.Events[0]
	if got.Type != "egress.denied" || got.Count != 2 || got.ProxyID != "10.42.0.17" {
		t.Fatalf("event = %+v, want aggregated denied event", got)
	}
	if got.WorkloadName != "test-workload" || got.SourcePolicyName != "source-policy" || got.Destination == nil || got.Destination.Host != "example.com" {
		t.Fatalf("event = %+v, want workload, source policy, and destination", got)
	}
}

func TestEventReporterIgnoresAllowedEvents(t *testing.T) {
	reporter, err := NewEventReporter(EventReporterOptions{
		Endpoint:         "http://127.0.0.1:1/v1/events",
		ProxyID:          "10.42.0.17",
		WorkloadIdentity: testWorkloadIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	reporter.RecordDecision(DecisionEvent{
		ID:       1,
		At:       time.Now().UTC(),
		Decision: "allowed",
		Message:  "allowed request method=GET destination=example.com:80",
	})
	if err := reporter.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v, want nil without outbound request", err)
	}
}

func TestEmptyEgressPolicyDeniesAllRequests(t *testing.T) {
	log := NewMemoryEventLog()
	proxy := NewProxyServer(CompiledPolicy{
		Version:    "airlock.dev/v1alpha1",
		PolicyName: "deny-all",
		Workload: WorkloadIdentity{
			SPIFFEID: testWorkloadIdentity,
		},
		Egress: []EgressRule{},
	}, staticSecretProvider{value: "test-token"}, log)
	proxyAddr := startProxy(t, proxy)

	response := sendProxyRequest(t, proxyAddr, "GET http://example.com/resource HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

	if !strings.HasPrefix(response, "HTTP/1.1 403 Forbidden") {
		t.Fatalf("response = %q, want 403", response)
	}
	if !strings.Contains(strings.Join(log.Entries(), "\n"), "denied request") {
		t.Fatalf("logs = %q, want denied request", log.Entries())
	}
}

func TestHTTPSConnectIsInterceptedRewrittenAndRedacted(t *testing.T) {
	seenHeaders := make(chan http.Header, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders <- r.Header.Clone()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := splitHostPort(upstreamURL.Host, 443)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := GenerateCertificateAuthority("airlock test mitm ca")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCertificateAuthority(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	log := NewMemoryEventLog()
	proxy := NewProxyServerWithOptions(
		testPolicyWithScheme("https", host, port),
		staticSecretProvider{value: "test-token"},
		log,
		ProxyServerOptions{
			MITMCA: ca,
			UpstreamTLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	)
	proxyAddr := startProxy(t, proxy)

	conn, err := net.Dial("tcp", proxyAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamURL.Host, upstreamURL.Host); err != nil {
		t.Fatal(err)
	}
	if status := readResponseStatus(t, conn); !strings.Contains(status, "200 Connection Established") {
		t.Fatalf("CONNECT response = %q, want 200", status)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    ca.CertPool(),
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(
		tlsConn,
		"GET /v1/models HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer workload-token\r\nConnection: close\r\n\r\n",
		upstreamURL.Host,
	); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(response), "HTTP/1.1 200 OK") {
		t.Fatalf("response = %q, want 200", string(response))
	}

	headers := recvHeaders(t, seenHeaders)
	if got := headers.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want injected token", got)
	}
	if got := headers.Get("Proxy-Authorization"); got != "" {
		t.Fatalf("Proxy-Authorization = %q, want stripped", got)
	}
	logs := strings.Join(log.Entries(), "\n")
	if strings.Contains(logs, "test-token") {
		t.Fatalf("logs leaked secret: %s", logs)
	}
	if !strings.Contains(logs, Redacted) {
		t.Fatalf("logs = %q, want redacted marker", logs)
	}
}

func TestHTTPSConnectWithoutMITMTunnelsAllowedDestinationWithNoRewrites(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := splitHostPort(upstreamURL.Host, 443)
	if err != nil {
		t.Fatal(err)
	}

	log := NewMemoryEventLog()
	proxy := NewProxyServer(CompiledPolicy{
		Version:    "airlock.dev/v1alpha1",
		PolicyName: "tunnel-only",
		Workload: WorkloadIdentity{
			SPIFFEID: testWorkloadIdentity,
		},
		Egress: []EgressRule{{
			Name:   "tls-upstream",
			Scheme: "https",
			Host:   host,
			Port:   uint32(port),
		}},
	}, staticSecretProvider{value: "unused"}, log)
	proxyAddr := startProxy(t, proxy)

	conn, err := net.Dial("tcp", proxyAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamURL.Host, upstreamURL.Host); err != nil {
		t.Fatal(err)
	}
	if status := readResponseStatus(t, conn); !strings.Contains(status, "200 Connection Established") {
		t.Fatalf("CONNECT response = %q, want 200", status)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstreamURL.Host); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(response), "HTTP/1.1 200 OK") {
		t.Fatalf("response = %q, want 200", string(response))
	}
	if !strings.Contains(strings.Join(log.Entries(), "\n"), "allowed CONNECT tunnel") {
		t.Fatalf("logs = %q, want allowed CONNECT tunnel", log.Entries())
	}
}

func TestExtProcAllowedRequestReturnsHeaderMutationAndRedactsLogs(t *testing.T) {
	log := NewMemoryEventLog()
	decision, err := EvaluateExtProcHeaders(
		testPolicy("api.example.test", 80),
		[]Header{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "api.example.test"},
			{Name: ":path", Value: "/v1/models"},
		},
		staticSecretProvider{value: "test-token"},
		log,
	)
	if err != nil {
		t.Fatal(err)
	}
	logs := strings.Join(log.Entries(), "\n")

	want := ExtProcDecision{
		Continue:  true,
		Mutations: []Header{{Name: "Authorization", Value: "Bearer test-token"}},
	}
	if !decision.Equal(want) {
		t.Fatalf("decision = %+v, want %+v", decision, want)
	}
	if strings.Contains(logs, "test-token") {
		t.Fatalf("logs leaked secret: %s", logs)
	}
	if !strings.Contains(logs, Redacted) {
		t.Fatalf("logs = %q, want redacted marker", logs)
	}
}

func TestExtProcDeniedRequestReturnsImmediateDeny(t *testing.T) {
	log := NewMemoryEventLog()
	decision, err := EvaluateExtProcHeaders(
		testPolicy("allowed.example.test", 80),
		[]Header{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "denied.example.test"},
		},
		staticSecretProvider{value: "test-token"},
		log,
	)
	if err != nil {
		t.Fatal(err)
	}

	want := ExtProcDecision{
		Deny:    true,
		Status:  403,
		Body:    "egress denied",
		Details: "airlock_egress_denied",
	}
	if !decision.Equal(want) {
		t.Fatalf("decision = %+v, want %+v", decision, want)
	}
	if !strings.Contains(strings.Join(log.Entries(), "\n"), "denied ext_proc request") {
		t.Fatalf("logs = %q, want denied ext_proc request", log.Entries())
	}
}

func TestExtProcAllowedConnectReturnsContinueWithoutHeaderMutation(t *testing.T) {
	log := NewMemoryEventLog()
	decision, err := EvaluateExtProcHeaders(
		testPolicyWithScheme("https", "api.example.test", 443),
		[]Header{
			{Name: ":method", Value: "CONNECT"},
			{Name: ":authority", Value: "api.example.test:443"},
		},
		staticSecretProvider{value: "test-token"},
		log,
	)
	if err != nil {
		t.Fatal(err)
	}

	want := ExtProcDecision{Continue: true}
	if !decision.Equal(want) {
		t.Fatalf("decision = %+v, want %+v", decision, want)
	}
	logs := strings.Join(log.Entries(), "\n")
	if !strings.Contains(logs, "allowed ext_proc CONNECT") {
		t.Fatalf("logs = %q, want allowed CONNECT", logs)
	}
	if strings.Contains(logs, "test-token") || strings.Contains(logs, Redacted) {
		t.Fatalf("CONNECT logs unexpectedly included secret material: %s", logs)
	}
}

func TestExtProcDeniedConnectReturnsImmediateDeny(t *testing.T) {
	log := NewMemoryEventLog()
	decision, err := EvaluateExtProcHeaders(
		testPolicyWithScheme("https", "allowed.example.test", 443),
		[]Header{
			{Name: ":method", Value: "CONNECT"},
			{Name: ":authority", Value: "denied.example.test:443"},
		},
		staticSecretProvider{value: "test-token"},
		log,
	)
	if err != nil {
		t.Fatal(err)
	}

	want := ExtProcDecision{
		Deny:    true,
		Status:  403,
		Body:    "egress denied",
		Details: "airlock_egress_denied",
	}
	if !decision.Equal(want) {
		t.Fatalf("decision = %+v, want %+v", decision, want)
	}
	logs := strings.Join(log.Entries(), "\n")
	if !strings.Contains(logs, "denied ext_proc request") || !strings.Contains(logs, "method=CONNECT") {
		t.Fatalf("logs = %q, want denied CONNECT", logs)
	}
}

func TestEnvFileSecretProviderReadsEnvAndFileValues(t *testing.T) {
	t.Setenv("AIRLOCK_ENV_FILE_TEST_TOKEN", "env-token")
	provider := EnvFileSecretProvider{}

	envValue, err := provider.Resolve(SecretRef{Provider: "env", Env: "AIRLOCK_ENV_FILE_TEST_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if envValue != "env-token" {
		t.Fatalf("env value = %q, want env-token", envValue)
	}

	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileValue, err := provider.Resolve(SecretRef{Provider: "file", File: path})
	if err != nil {
		t.Fatal(err)
	}
	if fileValue != "file-token" {
		t.Fatalf("file value = %q, want file-token", fileValue)
	}
}

func TestLocalPolicyProviderLoadsSharedLocalHTTPFixture(t *testing.T) {
	policy, err := NewLocalPolicyProvider("../../../fixtures/compiled/local-http.yaml").Load()
	if err != nil {
		t.Fatal(err)
	}

	if policy.PolicyName != "local-http" {
		t.Fatalf("policyName = %q, want local-http", policy.PolicyName)
	}
	if policy.Egress[0].Host != "127.0.0.1" {
		t.Fatalf("host = %q, want 127.0.0.1", policy.Egress[0].Host)
	}
	if policy.Egress[0].Port != 18081 {
		t.Fatalf("port = %d, want 18081", policy.Egress[0].Port)
	}
}

func TestControlPlanePolicyProviderFetchesCompiledPolicy(t *testing.T) {
	policy := testPolicy("api.example.test", 80)
	body, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	baseURL, requests := startControlPlane(t, body, 200)

	got, err := NewControlPlanePolicyProvider(baseURL, policy.Workload.SPIFFEID, "dev-token").Load()
	if err != nil {
		t.Fatal(err)
	}
	request := recvString(t, requests)

	if got.PolicyName != policy.PolicyName {
		t.Fatalf("policyName = %q, want %q", got.PolicyName, policy.PolicyName)
	}
	if got.Version != policy.Version {
		t.Fatalf("version = %q, want %q", got.Version, policy.Version)
	}
	if !strings.Contains(request, "GET /v1/policies/spiffe%3A%2F%2Fairlock.local%2Fns%2Fdemo%2Fsa%2Fcode-agent%2Fcomponent%2Fairlock-proxy-worker HTTP/1.1") {
		t.Fatalf("request = %q, want encoded workload path", request)
	}
	if !strings.Contains(request, "Authorization: Bearer dev-token") {
		t.Fatalf("request = %q, want dev token auth", request)
	}
}

func TestControlPlanePolicyProviderErrorsOnNon200(t *testing.T) {
	baseURL, _ := startControlPlane(t, []byte(`{"error":"policy not found"}`), 404)

	_, err := NewControlPlanePolicyProvider(baseURL, "spiffe://airlock.local/ns/demo/sa/missing", "").Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-200 error")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("error = %q, want HTTP 404", err)
	}
}

func startProxy(t *testing.T, proxy *ProxyServer) net.Addr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		_ = proxy.ServeLimit(listener, 1)
	}()
	return listener.Addr()
}

func startUpstream(t *testing.T) (*net.TCPAddr, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 1)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := readHTTPRequestBytes(conn)
		requests <- string(data)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}()

	return listener.Addr().(*net.TCPAddr), requests
}

func startControlPlane(t *testing.T, body []byte, status int) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 1)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := readHTTPRequestBytes(conn)
		requests <- string(data)
		reason := "Error"
		if status == 200 {
			reason = "OK"
		}
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", status, reason, len(body))
		_, _ = conn.Write(body)
	}()

	return "http://" + listener.Addr().String(), requests
}

func sendProxyRequest(t *testing.T, addr net.Addr, request string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return string(response)
}

func recvString(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for request")
		return ""
	}
}

func recvHeaders(t *testing.T, ch <-chan http.Header) http.Header {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for request")
		return nil
	}
}

func readResponseStatus(t *testing.T, conn net.Conn) string {
	t.Helper()
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return strings.TrimSpace(status)
}
