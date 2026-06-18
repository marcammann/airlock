package builtin

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	workersecrets "github.com/marcammann/airlock/internal/proxyworker/secrets"
	workertel "github.com/marcammann/airlock/internal/proxyworker/telemetry"
)

type staticSecretProvider struct {
	value string
}

func (p staticSecretProvider) Resolve(workersecrets.SecretRef) (string, error) {
	return p.value, nil
}

func testPolicy(scheme, host string, port uint32, rewrites []airlockv1.RewriteRule) airlockv1.CompiledPolicy {
	return airlockv1.CompiledPolicy{
		Version:    airlockv1.APIVersion,
		PolicyName: "test-policy",
		Egress: []airlockv1.EgressRule{{
			Name:     "allowed",
			Scheme:   scheme,
			Host:     host,
			Port:     port,
			Rewrites: rewrites,
		}},
	}
}

func authRewrite() airlockv1.RewriteRule {
	return airlockv1.RewriteRule{
		Target:        "header",
		Name:          "Authorization",
		ValueTemplate: "Bearer {{secret}}",
		ValueFrom: airlockv1.SecretRef{
			Provider: "env",
			Name:     "test-token",
			Env:      "AIRLOCK_TEST_TOKEN",
		},
	}
}

func TestGoProxyRequestHookAllowsAndRewritesHTTP(t *testing.T) {
	proxy := NewProxyServer(
		testPolicy("http", "api.example.test", 80, []airlockv1.RewriteRule{authRewrite()}),
		staticSecretProvider{value: "test-token"},
		workertel.NewMemoryEventLog(),
	)
	req, err := http.NewRequest(http.MethodGet, "http://api.example.test/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &goproxy.ProxyCtx{Req: req}

	gotReq, gotResp := proxy.handleGoProxyRequest(req, ctx)
	if gotResp != nil {
		t.Fatalf("response = %v, want nil allowed response", gotResp)
	}
	if got := gotReq.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want rewritten bearer token", got)
	}
	metadata, ok := ctx.UserData.(goProxyRequestMetadata)
	if !ok {
		t.Fatalf("ctx.UserData = %T, want goProxyRequestMetadata", ctx.UserData)
	}
	if metadata.Rule == nil || metadata.Rule.Name != "allowed" {
		t.Fatalf("metadata rule = %+v, want allowed rule", metadata.Rule)
	}
}

func TestGoProxyRequestHookDeniesBeforeTransport(t *testing.T) {
	proxy := NewProxyServer(
		testPolicy("http", "api.example.test", 80, nil),
		staticSecretProvider{value: "unused"},
		workertel.NewMemoryEventLog(),
	)
	req, err := http.NewRequest(http.MethodGet, "http://blocked.example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, gotResp := proxy.handleGoProxyRequest(req, &goproxy.ProxyCtx{Req: req})
	if gotResp == nil {
		t.Fatal("response = nil, want forbidden response")
	}
	if gotResp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", gotResp.StatusCode)
	}
}

func TestGoProxyConnectHookTunnelsAllowedDestinationWithoutRewrites(t *testing.T) {
	proxy := NewProxyServer(
		testPolicy("https", "api.example.test", 443, nil),
		staticSecretProvider{value: "unused"},
		workertel.NewMemoryEventLog(),
	)

	action, host := proxy.handleGoProxyConnect("api.example.test:443", &goproxy.ProxyCtx{})
	if host != "api.example.test:443" {
		t.Fatalf("host = %q, want original host", host)
	}
	if action.Action != goproxy.ConnectAccept {
		t.Fatalf("connect action = %v, want ConnectAccept", action.Action)
	}
}

func TestGoProxyConnectHookRequiresMITMForHTTPSRewrites(t *testing.T) {
	proxy := NewProxyServer(
		testPolicy("https", "api.example.test", 443, []airlockv1.RewriteRule{authRewrite()}),
		staticSecretProvider{value: "test-token"},
		workertel.NewMemoryEventLog(),
	)

	action, _ := proxy.handleGoProxyConnect("api.example.test:443", &goproxy.ProxyCtx{})
	if action.Action != goproxy.ConnectHijack {
		t.Fatalf("connect action = %v, want ConnectHijack error response", action.Action)
	}
}

func TestMaxReadCloserAllowsExactLimit(t *testing.T) {
	var exceeded bool
	reader := &maxReadCloser{
		ReadCloser: io.NopCloser(strings.NewReader("12345678")),
		max:        8,
		onExceeded: func() { exceeded = true },
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "12345678" {
		t.Fatalf("body = %q, want exact limit body", body)
	}
	if exceeded {
		t.Fatal("overflow callback fired for exact limit body")
	}
}

func TestMaxReadCloserErrorsWhenBodyExceedsLimit(t *testing.T) {
	var exceeded int
	reader := &maxReadCloser{
		ReadCloser: io.NopCloser(strings.NewReader("123456789")),
		max:        8,
		onExceeded: func() { exceeded++ },
	}

	body, err := io.ReadAll(reader)
	if !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("ReadAll error = %v, want errResponseTooLarge", err)
	}
	if string(body) != "12345678" {
		t.Fatalf("body = %q, want body capped at limit", body)
	}
	if exceeded != 1 {
		t.Fatalf("overflow callback count = %d, want 1", exceeded)
	}
}
