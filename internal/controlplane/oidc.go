package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type OIDCConfig struct {
	Issuer      string
	Audience    string
	JWKSURL     string
	GroupsClaim string
	RolesClaim  string
	HTTPClient  *http.Client
}

type OIDCAuthenticator struct {
	issuer      string
	audience    string
	jwksURL     string
	groupsClaim string
	rolesClaim  string
	client      *http.Client

	mu        sync.RWMutex
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
}

func NewOIDCAuthenticator(ctx context.Context, config OIDCConfig) (*OIDCAuthenticator, error) {
	issuer := strings.TrimRight(strings.TrimSpace(config.Issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("OIDC issuer is required")
	}
	audience := strings.TrimSpace(config.Audience)
	if audience == "" {
		return nil, fmt.Errorf("OIDC audience is required")
	}
	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	jwksURL := strings.TrimSpace(config.JWKSURL)
	if jwksURL == "" {
		discoveryURL := issuer + "/.well-known/openid-configuration"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch OIDC discovery: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch OIDC discovery: HTTP %d", resp.StatusCode)
		}
		var doc struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode OIDC discovery: %w", err)
		}
		jwksURL = strings.TrimSpace(doc.JWKSURI)
		if jwksURL == "" {
			return nil, fmt.Errorf("OIDC discovery missing jwks_uri")
		}
	}

	authenticator := &OIDCAuthenticator{
		issuer:      issuer,
		audience:    audience,
		jwksURL:     jwksURL,
		groupsClaim: strings.TrimSpace(config.GroupsClaim),
		rolesClaim:  strings.TrimSpace(config.RolesClaim),
		client:      client,
	}
	if authenticator.groupsClaim == "" {
		authenticator.groupsClaim = "groups"
	}
	if authenticator.rolesClaim == "" {
		authenticator.rolesClaim = "roles"
	}
	if err := authenticator.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	return authenticator, nil
}

func (a *OIDCAuthenticator) Authenticate(ctx context.Context, token string) (AdminPrincipal, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return AdminPrincipal{}, fmt.Errorf("bearer token is required")
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
	})
	if err != nil {
		return AdminPrincipal{}, fmt.Errorf("parse JWT: %w", err)
	}

	var lastErr error
	for _, key := range a.keys(parsed) {
		var claims jwt.Claims
		privateClaims := map[string]any{}
		if err := parsed.Claims(key, &claims, &privateClaims); err != nil {
			lastErr = err
			continue
		}
		if err := claims.ValidateWithLeeway(jwt.Expected{
			Issuer:      a.issuer,
			AnyAudience: jwt.Audience{a.audience},
			Time:        time.Now(),
		}, time.Minute); err != nil {
			return AdminPrincipal{}, fmt.Errorf("validate JWT claims: %w", err)
		}
		return principalFromClaims(claims, privateClaims, a.groupsClaim, a.rolesClaim), nil
	}

	if err := a.refreshJWKS(ctx); err != nil {
		return AdminPrincipal{}, err
	}
	for _, key := range a.keys(parsed) {
		var claims jwt.Claims
		privateClaims := map[string]any{}
		if err := parsed.Claims(key, &claims, &privateClaims); err != nil {
			lastErr = err
			continue
		}
		if err := claims.ValidateWithLeeway(jwt.Expected{
			Issuer:      a.issuer,
			AnyAudience: jwt.Audience{a.audience},
			Time:        time.Now(),
		}, time.Minute); err != nil {
			return AdminPrincipal{}, fmt.Errorf("validate JWT claims: %w", err)
		}
		return principalFromClaims(claims, privateClaims, a.groupsClaim, a.rolesClaim), nil
	}

	if lastErr != nil {
		return AdminPrincipal{}, fmt.Errorf("verify JWT signature: %w", lastErr)
	}
	return AdminPrincipal{}, fmt.Errorf("verify JWT signature: no matching key")
}

func (a *OIDCAuthenticator) keys(token *jwt.JSONWebToken) []any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.jwks == nil {
		return nil
	}
	keyID := ""
	if len(token.Headers) > 0 {
		keyID = token.Headers[0].KeyID
	}
	var out []any
	if keyID != "" {
		for _, key := range a.jwks.Key(keyID) {
			if key.Valid() {
				out = append(out, key.Key)
			}
		}
		return out
	}
	for _, key := range a.jwks.Keys {
		if key.Valid() {
			out = append(out, key.Key)
		}
	}
	return out
}

func (a *OIDCAuthenticator) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch OIDC JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch OIDC JWKS: HTTP %d", resp.StatusCode)
	}
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decode OIDC JWKS: %w", err)
	}
	a.mu.Lock()
	a.jwks = &jwks
	a.fetchedAt = time.Now()
	a.mu.Unlock()
	return nil
}

func principalFromClaims(claims jwt.Claims, privateClaims map[string]any, groupsClaim string, rolesClaim string) AdminPrincipal {
	return AdminPrincipal{
		Subject: claims.Subject,
		Email:   stringClaim(privateClaims, "email"),
		Groups:  stringListClaim(privateClaims, groupsClaim),
		Roles:   stringListClaim(privateClaims, rolesClaim),
	}
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func stringListClaim(claims map[string]any, name string) []string {
	switch value := claims[name].(type) {
	case []string:
		return value
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return []string{value}
	default:
		return nil
	}
}
