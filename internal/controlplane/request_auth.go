package controlplane

import controlauth "github.com/marcammann/airlock/internal/controlplane/auth"

// RequestAuthenticator authenticates one HTTP request.
type RequestAuthenticator = controlauth.RequestAuthenticator

// AuthenticatorChain tries multiple request authenticators.
type AuthenticatorChain = controlauth.AuthenticatorChain

// APIKeyAuthenticator validates bearer API keys.
type APIKeyAuthenticator = controlauth.APIKeyAuthenticator

// APIKey configures one API key principal.
type APIKey = controlauth.APIKey

// OIDCRequestAuthenticator adapts OIDC token validation to request auth.
type OIDCRequestAuthenticator = controlauth.OIDCRequestAuthenticator

// SPIFFERequestAuthenticator authenticates requests by SPIFFE peer identity.
type SPIFFERequestAuthenticator = controlauth.SPIFFERequestAuthenticator

// NewAuthenticatorChain creates a chain of request authenticators.
func NewAuthenticatorChain(providers []RequestAuthenticator) *AuthenticatorChain {
	return controlauth.NewAuthenticatorChain(providers)
}

// NewAPIKeyAuthenticator creates an API key request authenticator.
func NewAPIKeyAuthenticator(name string, keys []APIKey) (*APIKeyAuthenticator, error) {
	return controlauth.NewAPIKeyAuthenticator(name, keys)
}

// HashAPIKey hashes a bearer token for config storage.
func HashAPIKey(token string) string {
	return controlauth.HashAPIKey(token)
}

// NewOIDCRequestAuthenticator creates an OIDC request authenticator.
func NewOIDCRequestAuthenticator(name string, authenticator *OIDCAuthenticator) *OIDCRequestAuthenticator {
	return controlauth.NewOIDCRequestAuthenticator(name, authenticator)
}

// NewSPIFFERequestAuthenticator creates a SPIFFE request authenticator.
func NewSPIFFERequestAuthenticator(name string) *SPIFFERequestAuthenticator {
	return controlauth.NewSPIFFERequestAuthenticator(name)
}
