package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

const maxOIDCFetchBytes = 1 << 20

// OIDCConfig configures an OIDC token verifier.
type OIDCConfig struct {
	Issuer         string
	Audience       string
	JWKSURL        string
	GroupsClaim    string
	RolesClaim     string
	RequiredClaims map[string]string
	HTTPClient     *http.Client
}

// OIDCAuthenticator verifies OIDC ID tokens and maps claims to admin principals.
type OIDCAuthenticator struct {
	issuer         string
	audience       string
	groupsClaim    string
	rolesClaim     string
	client         *http.Client
	requiredClaims map[string]string
	verifier       *oidc.IDTokenVerifier
}

// NewOIDCAuthenticator creates an OIDC authenticator from discovery metadata or an explicit JWKS URL.
func NewOIDCAuthenticator(ctx context.Context, config OIDCConfig) (*OIDCAuthenticator, error) {
	issuer := strings.TrimRight(strings.TrimSpace(config.Issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("oidc issuer is required")
	}
	audience := strings.TrimSpace(config.Audience)
	if audience == "" {
		return nil, fmt.Errorf("oidc audience is required")
	}
	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	client = boundedOIDCClient(client)
	ctx = oidc.ClientContext(ctx, client)
	verifierConfig := &oidc.Config{ClientID: audience}
	var verifier *oidc.IDTokenVerifier
	if jwksURL := strings.TrimSpace(config.JWKSURL); jwksURL != "" {
		verifier = oidc.NewVerifier(issuer, oidc.NewRemoteKeySet(ctx, jwksURL), verifierConfig)
	} else {
		provider, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			return nil, fmt.Errorf("fetch OIDC discovery: %w", err)
		}
		verifier = provider.Verifier(verifierConfig)
	}

	authenticator := &OIDCAuthenticator{
		issuer:      issuer,
		audience:    audience,
		groupsClaim: strings.TrimSpace(config.GroupsClaim),
		rolesClaim:  strings.TrimSpace(config.RolesClaim),
		client:      client,
		verifier:    verifier,
	}
	if len(config.RequiredClaims) > 0 {
		authenticator.requiredClaims = map[string]string{}
		for name, value := range config.RequiredClaims {
			name = strings.TrimSpace(name)
			value = strings.TrimSpace(value)
			if name != "" && value != "" {
				authenticator.requiredClaims[name] = value
			}
		}
	}
	if authenticator.groupsClaim == "" {
		authenticator.groupsClaim = "groups"
	}
	if authenticator.rolesClaim == "" {
		authenticator.rolesClaim = "roles"
	}
	return authenticator, nil
}

type limitResponseBodyTransport struct {
	base http.RoundTripper
	max  int64
}

func (t limitResponseBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		resp.Body = &maxBytesReadCloser{rc: resp.Body, max: t.max}
	}
	return resp, nil
}

type maxBytesReadCloser struct {
	rc   io.ReadCloser
	max  int64
	read int64
}

func (r *maxBytesReadCloser) Read(p []byte) (int, error) {
	if r.max <= 0 {
		return r.rc.Read(p)
	}
	remaining := r.max + 1 - r.read
	if remaining <= 0 {
		return 0, fmt.Errorf("oidc response body exceeds %d bytes", r.max)
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.rc.Read(p)
	r.read += int64(n)
	if r.read > r.max {
		overflow := int(r.read - r.max)
		return n - overflow, fmt.Errorf("oidc response body exceeds %d bytes", r.max)
	}
	return n, err
}

func (r *maxBytesReadCloser) Close() error {
	return r.rc.Close()
}

func boundedOIDCClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	out := *client
	base := out.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	out.Transport = limitResponseBodyTransport{base: base, max: maxOIDCFetchBytes}
	return &out
}

// Authenticate verifies a raw OIDC token and returns its admin principal.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, token string) (AdminPrincipal, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return AdminPrincipal{}, fmt.Errorf("bearer token is required")
	}
	ctx = oidc.ClientContext(ctx, a.client)
	idToken, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return AdminPrincipal{}, fmt.Errorf("verify OIDC token: %w", err)
	}
	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return AdminPrincipal{}, fmt.Errorf("decode OIDC claims: %w", err)
	}
	if err := a.validateRequiredClaims(idToken, claims); err != nil {
		return AdminPrincipal{}, err
	}
	return principalFromClaims(idToken, claims, a.groupsClaim, a.rolesClaim), nil
}

func (a *OIDCAuthenticator) validateRequiredClaims(idToken *oidc.IDToken, claims map[string]any) error {
	for name, want := range a.requiredClaims {
		var got string
		switch name {
		case "sub":
			got = idToken.Subject
		case "iss", "issuer":
			got = idToken.Issuer
		default:
			got = stringClaim(claims, name)
		}
		if got != want {
			return fmt.Errorf("required OIDC claim %q mismatch", name)
		}
	}
	return nil
}

func principalFromClaims(idToken *oidc.IDToken, claims map[string]any, groupsClaim string, rolesClaim string) AdminPrincipal {
	return AdminPrincipal{
		Subject: idToken.Subject,
		Email:   stringClaim(claims, "email"),
		Groups:  stringListClaim(claims, groupsClaim),
		Roles:   stringListClaim(claims, rolesClaim),
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
