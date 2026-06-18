package controlplane

import (
	"context"

	controlauth "github.com/marcammann/airlock/internal/controlplane/auth"
)

// OIDCConfig configures OIDC token validation.
type OIDCConfig = controlauth.OIDCConfig

// OIDCAuthenticator validates OIDC bearer tokens.
type OIDCAuthenticator = controlauth.OIDCAuthenticator

// NewOIDCAuthenticator creates an OIDC authenticator.
func NewOIDCAuthenticator(ctx context.Context, config OIDCConfig) (*OIDCAuthenticator, error) {
	return controlauth.NewOIDCAuthenticator(ctx, config)
}
