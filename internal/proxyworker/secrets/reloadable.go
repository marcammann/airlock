package secrets

import (
	"fmt"
	"sync/atomic"
)

// ReloadableSecretProvider atomically swaps the active provider during policy reloads.
type ReloadableSecretProvider struct {
	current atomic.Value
}

// NewReloadableSecretProvider creates a reloadable wrapper around provider.
func NewReloadableSecretProvider(provider SecretProvider) *ReloadableSecretProvider {
	reloadable := &ReloadableSecretProvider{}
	reloadable.Update(provider)
	return reloadable
}

// Update replaces the provider used for subsequent secret resolutions.
func (p *ReloadableSecretProvider) Update(provider SecretProvider) {
	if provider == nil {
		provider = NewEnvFileSecretProvider(EnvFileSecretProviderOptions{})
	}
	p.current.Store(provider)
}

// Resolve delegates to the current provider.
func (p *ReloadableSecretProvider) Resolve(ref SecretRef) (string, error) {
	current, ok := p.current.Load().(SecretProvider)
	if !ok || current == nil {
		return "", fmt.Errorf("secret provider is not configured")
	}
	return current.Resolve(ref)
}
