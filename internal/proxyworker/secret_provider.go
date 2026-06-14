package proxyworker

// SecretProvider resolves policy SecretRef values into concrete secret values.
//
// Providers should fail closed: if a referenced secret is missing, expired, or
// unavailable, Resolve must return an error rather than an empty value.
type SecretProvider interface {
	Resolve(SecretRef) (string, error)
}
