package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// RequestAuthenticator authenticates an HTTP request into an admin principal.
type RequestAuthenticator interface {
	AuthenticateRequest(ctx context.Context, r *http.Request) (AdminPrincipal, error)
}

// TokenAuthenticator authenticates a bearer token into an admin principal.
type TokenAuthenticator interface {
	Authenticate(ctx context.Context, token string) (AdminPrincipal, error)
}

// AuthenticatorChain tries request authenticators in order.
type AuthenticatorChain struct {
	providers []RequestAuthenticator
}

// NewAuthenticatorChain creates a chain from configured authenticators.
func NewAuthenticatorChain(providers []RequestAuthenticator) *AuthenticatorChain {
	if len(providers) == 0 {
		return nil
	}
	return &AuthenticatorChain{providers: append([]RequestAuthenticator(nil), providers...)}
}

// AuthenticateRequest returns the first successful principal from the chain.
func (c *AuthenticatorChain) AuthenticateRequest(ctx context.Context, r *http.Request) (AdminPrincipal, error) {
	if c == nil {
		return AdminPrincipal{}, fmt.Errorf("authenticator chain is not configured")
	}
	var lastErr error
	for _, provider := range c.providers {
		principal, err := provider.AuthenticateRequest(ctx, r)
		if err == nil {
			return principal, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return AdminPrincipal{}, lastErr
	}
	return AdminPrincipal{}, fmt.Errorf("no authenticator accepted request")
}

// APIKeyAuthenticator authenticates bearer tokens against configured API key hashes.
type APIKeyAuthenticator struct {
	name string
	keys map[string]AdminPrincipal
}

// APIKey describes one accepted API key for admin or enrollment auth.
type APIKey struct {
	ID     string
	Hash   string
	Value  string
	Env    string
	File   string
	Groups []string
	Roles  []string
}

// NewAPIKeyAuthenticator creates an API key authenticator from static keys.
func NewAPIKeyAuthenticator(name string, keys []APIKey) (*APIKeyAuthenticator, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "api-key"
	}
	out := &APIKeyAuthenticator{name: name, keys: map[string]AdminPrincipal{}}
	for _, key := range keys {
		id := strings.TrimSpace(key.ID)
		if id == "" {
			return nil, fmt.Errorf("api key provider %q has key with empty id", name)
		}
		hash, err := resolveAPIKeyHash(key)
		if err != nil {
			return nil, fmt.Errorf("api key %q: %w", id, err)
		}
		if _, ok := out.keys[hash]; ok {
			return nil, fmt.Errorf("api key provider %q has duplicate key hash", name)
		}
		out.keys[hash] = AdminPrincipal{
			Provider: name,
			Subject:  "key:" + id,
			Groups:   append([]string(nil), key.Groups...),
			Roles:    append([]string(nil), key.Roles...),
		}
	}
	if len(out.keys) == 0 {
		return nil, fmt.Errorf("api key provider %q requires at least one key", name)
	}
	return out, nil
}

// AuthenticateRequest validates a bearer token from the Authorization header.
func (a *APIKeyAuthenticator) AuthenticateRequest(_ context.Context, r *http.Request) (AdminPrincipal, error) {
	token := BearerToken(r)
	if token == "" {
		return AdminPrincipal{}, fmt.Errorf("api key bearer token is required")
	}
	principal, ok := a.keys[HashAPIKey(token)]
	if !ok {
		return AdminPrincipal{}, fmt.Errorf("api key is invalid")
	}
	return principal, nil
}

func resolveAPIKeyHash(key APIKey) (string, error) {
	hash := strings.TrimSpace(key.Hash)
	if hash != "" {
		if !strings.HasPrefix(hash, "sha256:") {
			return "", fmt.Errorf("hash must use sha256:<hex>")
		}
		return hash, nil
	}
	value := strings.TrimSpace(key.Value)
	if value == "" && strings.TrimSpace(key.Env) != "" {
		value = strings.TrimSpace(os.Getenv(strings.TrimSpace(key.Env)))
	}
	if value == "" && strings.TrimSpace(key.File) != "" {
		data, err := os.ReadFile(strings.TrimSpace(key.File))
		if err != nil {
			return "", fmt.Errorf("read key file: %w", err)
		}
		value = strings.TrimSpace(string(data))
	}
	if value == "" {
		return "", fmt.Errorf("one of hash, value, env, or file is required")
	}
	return HashAPIKey(value), nil
}

// HashAPIKey returns the stable sha256 hash representation of an API key.
func HashAPIKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// OIDCRequestAuthenticator adapts an OIDC token authenticator to HTTP requests.
type OIDCRequestAuthenticator struct {
	name          string
	authenticator TokenAuthenticator
}

// NewOIDCRequestAuthenticator creates an HTTP request authenticator for OIDC bearer tokens.
func NewOIDCRequestAuthenticator(name string, authenticator TokenAuthenticator) *OIDCRequestAuthenticator {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "oidc"
	}
	return &OIDCRequestAuthenticator{name: name, authenticator: authenticator}
}

// AuthenticateRequest validates an OIDC bearer token from the Authorization header.
func (a *OIDCRequestAuthenticator) AuthenticateRequest(ctx context.Context, r *http.Request) (AdminPrincipal, error) {
	if a.authenticator == nil {
		return AdminPrincipal{}, fmt.Errorf("oidc provider %q is not configured", a.name)
	}
	principal, err := a.authenticator.Authenticate(ctx, BearerToken(r))
	if err != nil {
		return AdminPrincipal{}, err
	}
	principal.Provider = a.name
	return principal, nil
}

// SPIFFERequestAuthenticator authenticates requests from TLS peer SPIFFE IDs.
type SPIFFERequestAuthenticator struct {
	name string
}

// NewSPIFFERequestAuthenticator creates a SPIFFE request authenticator.
func NewSPIFFERequestAuthenticator(name string) *SPIFFERequestAuthenticator {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "spiffe"
	}
	return &SPIFFERequestAuthenticator{name: name}
}

// AuthenticateRequest extracts the authenticated peer SPIFFE ID from request TLS state.
func (a *SPIFFERequestAuthenticator) AuthenticateRequest(_ context.Context, r *http.Request) (AdminPrincipal, error) {
	id, ok := PeerSPIFFEID(r)
	if !ok {
		return AdminPrincipal{}, fmt.Errorf("spiffe peer identity is required")
	}
	return AdminPrincipal{Provider: a.name, Subject: id}, nil
}

// BearerToken extracts a case-insensitive bearer token from Authorization.
func BearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	_, ok := strings.CutPrefix(strings.ToLower(value), "bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(value[len("Bearer "):])
}

// PeerSPIFFEID returns the SPIFFE ID from the first verified peer certificate.
func PeerSPIFFEID(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}

	id, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		return "", false
	}

	return id.String(), true
}
