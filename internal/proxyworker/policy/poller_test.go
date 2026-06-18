package policy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
)

const testWorkloadIdentity = "spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPolicyPollHandlesNotModified(t *testing.T) {
	var sawIfNoneMatch bool
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("If-None-Match"); got == `"v1"` {
			sawIfNoneMatch = true
		} else {
			t.Fatalf("If-None-Match = %q, want v1", got)
		}
		header := http.Header{}
		header.Set("ETag", `"v1"`)
		return &http.Response{
			StatusCode: http.StatusNotModified,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})}

	result, err := NewControlPlanePolicyProvider("http://control-plane.test", testWorkloadIdentity).Poll(context.Background(), client, `"v1"`)
	if err != nil {
		t.Fatal(err)
	}
	if !result.NotModified || result.ETag != `"v1"` || !sawIfNoneMatch {
		t.Fatalf("result = %+v sawIfNoneMatch=%t, want not-modified with ETag v1", result, sawIfNoneMatch)
	}
}

func TestPolicyPollRejectsOversizedResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(io.LimitReader(strings.NewReader(strings.Repeat("x", maxPolicyResponseBytes+2)), maxPolicyResponseBytes+2)),
			Request:    req,
		}, nil
	})}

	_, err := NewControlPlanePolicyProvider("http://control-plane.test", testWorkloadIdentity).Poll(context.Background(), client, "")
	if err == nil {
		t.Fatal("Poll() error = nil, want response size error")
	}
	if !strings.Contains(err.Error(), "policy response exceeds 4 MiB limit") {
		t.Fatalf("error = %q, want response size error", err)
	}
}

func TestPolicyPollerAppliesChangedPolicyAndSkipsNotModified(t *testing.T) {
	policy := testPolicy("api.example.test", 80)
	body, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var applyCount int
	var requests int
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Header.Get("If-None-Match") == `"v2"` {
			header := http.Header{}
			header.Set("ETag", `"v2"`)
			return &http.Response{
				StatusCode: http.StatusNotModified,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}
		header := http.Header{}
		header.Set("ETag", `"v2"`)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Request:    req,
		}, nil
	})}

	poller, err := NewPolicyPoller(PolicyPollerOptions{
		Provider:    NewControlPlanePolicyProvider("http://control-plane.test", testWorkloadIdentity),
		Client:      client,
		Interval:    time.Minute,
		InitialETag: `"v1"`,
		Apply: func(context.Context, CompiledPolicy) error {
			applyCount++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	changed, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !changed || applyCount != 1 || poller.etag != `"v2"` {
		t.Fatalf("first poll changed=%t applyCount=%d etag=%q, want changed once with v2", changed, applyCount, poller.etag)
	}

	changed, err = poller.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed || applyCount != 1 || poller.etag != `"v2"` {
		t.Fatalf("second poll changed=%t applyCount=%d etag=%q, want unchanged with v2", changed, applyCount, poller.etag)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want two polls", requests)
	}
}

func testPolicy(host string, port uint16) CompiledPolicy {
	return CompiledPolicy{
		Version:    airlockv1.APIVersion,
		PolicyName: "test-policy",
		Workload: airlockv1.WorkloadIdentity{
			SPIFFEID:       testWorkloadIdentity,
			Namespace:      "demo",
			ServiceAccount: "code-agent",
		},
		Egress: []airlockv1.EgressRule{{
			Name:   "local-upstream",
			Scheme: "http",
			Host:   host,
			Port:   uint32(port),
			Rewrites: []airlockv1.RewriteRule{{
				Target:        "header",
				Name:          "Authorization",
				ValueTemplate: "Bearer {{secret}}",
				ValueFrom: airlockv1.SecretRef{
					Provider: "env",
					Name:     "test-token",
					Env:      "AIRLOCK_TEST_TOKEN",
				},
			}},
		}},
	}
}
