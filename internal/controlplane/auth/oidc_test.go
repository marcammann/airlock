package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func TestStringListClaim(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"platform", "", 42, "security"},
		"roles":  "viewer",
	}
	groups := stringListClaim(claims, "groups")
	if len(groups) != 2 || groups[0] != "platform" || groups[1] != "security" {
		t.Fatalf("groups = %+v, want compact string list", groups)
	}
	roles := stringListClaim(claims, "roles")
	if len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("roles = %+v, want single string role", roles)
	}
}

func TestBoundedOIDCClientRejectsOversizedResponse(t *testing.T) {
	client := boundedOIDCClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maxOIDCFetchBytes+1))),
			Header:     make(http.Header),
		}, nil
	})})

	resp, err := client.Get("https://issuer.example.test/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if err == nil {
		t.Fatal("ReadAll() error = nil, want OIDC body limit error")
	}
	if !strings.Contains(err.Error(), "oidc response body exceeds") {
		t.Fatalf("error = %q, want OIDC body limit", err)
	}
}

func TestOIDCRejectsOversizedJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jwks_uri":"` + issuer + `/keys"}`))
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat("x", maxOIDCFetchBytes+1)))
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
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{
		"iss": issuer,
		"sub": "subject-1",
		"aud": []string{"airlock-web"},
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "oversized-jwks"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = authenticator.Authenticate(context.Background(), signed)
	if err == nil {
		t.Fatal("Authenticate() error = nil, want oversized JWKS failure")
	}
	if !strings.Contains(err.Error(), "oidc response body exceeds") {
		t.Fatalf("error = %q, want OIDC body limit", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
