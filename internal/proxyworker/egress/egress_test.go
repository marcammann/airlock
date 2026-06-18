package egress

import (
	"strings"
	"testing"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	workersecrets "github.com/marcammann/airlock/internal/proxyworker/secrets"
)

type staticSecretProvider struct {
	value string
}

func (p staticSecretProvider) Resolve(workersecrets.SecretRef) (string, error) {
	return p.value, nil
}

func TestFindEgressRuleMatchesSchemeHostAndPort(t *testing.T) {
	policy := CompiledPolicy{Egress: []airlockv1.EgressRule{{
		Name:   "api",
		Scheme: "https",
		Host:   "api.example.test",
		Port:   443,
	}}}

	rule := FindEgressRule(policy, Destination{Scheme: "HTTPS", Host: "API.EXAMPLE.TEST", Port: 443})
	if rule == nil || rule.Name != "api" {
		t.Fatalf("rule = %+v, want api", rule)
	}
	if got := FindEgressRule(policy, Destination{Scheme: "https", Host: "api.example.test", Port: 8443}); got != nil {
		t.Fatalf("rule = %+v, want no port mismatch", got)
	}
}

func TestApplyRewritesRedactsAndRejectsCRLF(t *testing.T) {
	headers := []Header{{Name: "User-Agent", Value: "test"}}
	var redactor Redactor
	err := ApplyRewrites(&headers, []airlockv1.RewriteRule{{
		Target:        "header",
		Name:          "Authorization",
		ValueTemplate: "Bearer {{secret}}",
		ValueFrom:     airlockv1.SecretRef{Provider: "env", Env: "TOKEN"},
	}}, staticSecretProvider{value: "secret-token"}, &redactor)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := HeaderValue(headers, "Authorization")
	if !ok || value != "Bearer secret-token" {
		t.Fatalf("Authorization = %q ok=%t, want rewritten header", value, ok)
	}
	if redactor.Redact("token=secret-token") != "token="+Redacted {
		t.Fatalf("redactor did not redact secret")
	}

	err = ApplyRewrites(&headers, []airlockv1.RewriteRule{{
		Target:    "header",
		Name:      "Authorization",
		ValueFrom: airlockv1.SecretRef{Provider: "env", Env: "TOKEN"},
	}}, staticSecretProvider{value: "bad\r\nX-Evil: yes"}, &redactor)
	if err == nil || !strings.Contains(err.Error(), "rewrite value contains CRLF") {
		t.Fatalf("error = %v, want CRLF validation error", err)
	}
}

func TestDestinationFromHeadersConnectDefaultsToHTTPS(t *testing.T) {
	destination, err := DestinationFromHeaders([]Header{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: "api.example.test:443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if destination.Scheme != "https" || destination.Host != "api.example.test" || destination.Port != 443 {
		t.Fatalf("destination = %+v, want https api.example.test:443", destination)
	}
}
