package auth

import (
	"context"
	"net/http"
	"testing"
)

func TestAPIKeyAuthenticatorAcceptsCaseInsensitiveBearerScheme(t *testing.T) {
	authenticator, err := NewAPIKeyAuthenticator("local", []APIKey{{ID: "console", Value: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"Bearer secret", "bearer secret", "BEARER secret"} {
		t.Run(header, func(t *testing.T) {
			request := &http.Request{Header: http.Header{"Authorization": []string{header}}}
			principal, err := authenticator.AuthenticateRequest(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if principal.Subject != "key:console" || principal.Provider != "local" {
				t.Fatalf("principal = %+v, want local key principal", principal)
			}
		})
	}
}

func TestAuthenticatorChainTriesProvidersInOrder(t *testing.T) {
	first, err := NewAPIKeyAuthenticator("first", []APIKey{{ID: "first", Value: "one"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAPIKeyAuthenticator("second", []APIKey{{ID: "second", Value: "two"}})
	if err != nil {
		t.Fatal(err)
	}
	chain := NewAuthenticatorChain([]RequestAuthenticator{first, second})
	request := &http.Request{Header: http.Header{"Authorization": []string{"Bearer two"}}}

	principal, err := chain.AuthenticateRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Provider != "second" {
		t.Fatalf("provider = %q, want second", principal.Provider)
	}
}
