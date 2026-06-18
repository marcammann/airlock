package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsHandlerExposesAirlockMetrics(t *testing.T) {
	ObserveProxyDecision("allowed")
	ObserveSecretResolve("vault", "success")
	ProxyHTTPMetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://proxy.test/", nil))
	ObserveControlPlaneRequest("worker", http.StatusTeapot)
	ObserveControlPlaneAuthFailure("spiffe")
	ObserveControlPlaneEventsIngested(2)
	ObserveControlPlaneReconcileDuration("vault", 25*time.Millisecond)
	SetControlPlaneActiveProxies(1)

	response := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := response.Body.String()
	for _, want := range []string{
		"airlock_proxy_decisions_total",
		`airlock_secret_resolve_total{provider="vault",result="success"}`,
		"airlock_proxy_request_duration_seconds_count",
		"airlock_proxy_active_connections",
		`airlock_cp_requests_total{code="418",surface="worker"}`,
		`airlock_cp_auth_failures_total{mode="spiffe"}`,
		"airlock_cp_events_ingested_total",
		`airlock_cp_reconcile_duration_seconds_count{kind="vault"}`,
		"airlock_cp_active_proxies",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics body missing %q:\n%s", want, body)
		}
	}
}

func TestControlPlaneHTTPMetricsHandlerRecordsStatus(t *testing.T) {
	handler := ControlPlaneHTTPMetricsHandler("admin", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/admin/policies", nil))

	response := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(response.Body.String(), `airlock_cp_requests_total{code="201",surface="admin"}`) {
		t.Fatalf("metrics body missing admin 201 request counter:\n%s", response.Body.String())
	}
}

func TestControlPlaneHTTPMetricsHandlerRecordsFirstStatus(t *testing.T) {
	handler := ControlPlaneHTTPMetricsHandler("admin", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.WriteHeader(http.StatusInternalServerError)
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/policies", nil))
	if response.Code != http.StatusCreated {
		t.Fatalf("response.Code = %d, want 201", response.Code)
	}

	metrics := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), `airlock_cp_requests_total{code="201",surface="admin"}`) {
		t.Fatalf("metrics body missing admin 201 request counter:\n%s", metrics.Body.String())
	}
}
