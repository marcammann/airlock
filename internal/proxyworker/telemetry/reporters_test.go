package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
)

const testWorkloadIdentity = "spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestEventReporterPostsAggregatedDeniedEvent(t *testing.T) {
	var payload eventReportPayload
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/events" {
			t.Fatalf("request = %s %s, want POST /v1/events", req.Method, req.URL.Path)
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatalf("decode event payload: %v", err)
		}
		return jsonResponse(http.StatusOK, `{}`), nil
	})}

	reporter, err := NewEventReporter(EventReporterOptions{
		Endpoint:          "http://control-plane.test/v1/events",
		ProxyID:           "10.42.0.17",
		ProxyType:         "http:builtin",
		WorkloadIdentity:  testWorkloadIdentity,
		WorkloadName:      "test-workload",
		WorkloadNamespace: "airlock-system",
		EffectiveVersion:  airlockv1.APIVersion,
		Client:            client,
		RatePerSecond:     10,
		Burst:             10,
		SourcePolicyByRule: map[string]airlockv1.PolicyRef{
			"example": {Name: "source-policy", Namespace: "airlock-system"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := DecisionEvent{
		ID:       7,
		At:       time.Now().UTC(),
		Decision: DecisionDeny,
		Message:  "denied request policy=test-policy policy_version=airlock.dev/v1alpha1 rule=example method=GET destination=example.com:80",
		Fields: map[string]string{
			"method":      "GET",
			"rule":        "example",
			"destination": "example.com:80",
		},
	}
	reporter.RecordDecision(event)
	event.ID = 8
	reporter.RecordDecision(event)
	if err := reporter.Flush(context.Background()); err != nil {
		t.Fatal(err)
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

func TestHeartbeatReporterPostsProxyStatus(t *testing.T) {
	log := NewMemoryEventLog()
	log.Record(DecisionAllow, "allowed request", map[string]string{"method": "GET", "destination": "github.com:443"})
	policyFetchedAt := time.Now().UTC()
	processStartedAt := policyFetchedAt.Add(-time.Minute)
	var payload proxyHeartbeatPayload
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/proxies/heartbeat" {
			t.Fatalf("request = %s %s, want POST /v1/proxies/heartbeat", req.Method, req.URL.Path)
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatalf("decode heartbeat: %v", err)
		}
		return jsonResponse(http.StatusOK, `{"ok":true}`), nil
	})}

	reporter, err := NewHeartbeatReporter(HeartbeatReporterOptions{
		BaseURL:           "http://control-plane.test",
		ProxyID:           "proxy-1",
		ProxyType:         "http:builtin",
		WorkloadIdentity:  testWorkloadIdentity,
		WorkloadName:      "test-policy",
		EffectiveVersion:  airlockv1.APIVersion,
		PolicyFetchedAt:   &policyFetchedAt,
		HeartbeatInterval: 10 * time.Second,
		ProcessStartedAt:  processStartedAt,
		Log:               log,
		Client:            client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Report(context.Background()); err != nil {
		t.Fatal(err)
	}

	if payload.ID != "proxy-1" || payload.WorkloadIdentity != testWorkloadIdentity || payload.ProxyType != "http:builtin" {
		t.Fatalf("payload identity = %+v, want proxy-1 test identity http:builtin", payload)
	}
	if !payload.PolicyFetched || payload.LastPolicyFetchAt == nil || payload.ProcessStartedAt == nil || payload.LastDecisionAt == nil {
		t.Fatalf("payload timestamps = %+v, want policy/process/decision timestamps", payload)
	}
	if payload.Decisions.Allowed != 1 || payload.Decisions.Denied != 0 || payload.Decisions.ProxyError != 0 {
		t.Fatalf("decisions = %+v, want one allowed decision", payload.Decisions)
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}
