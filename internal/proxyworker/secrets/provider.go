// Package secrets resolves proxy-worker secret references.
package secrets

import (
	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	"github.com/marcammann/airlock/internal/telemetry"
)

// SecretRef is the policy reference that identifies where a secret value lives.
type SecretRef = airlockv1.SecretRef

// CompiledPolicy is the worker policy format inspected for secret references.
type CompiledPolicy = airlockv1.CompiledPolicy

// CompiledVaultProvider contains the Vault settings embedded in a compiled policy.
type CompiledVaultProvider = airlockv1.CompiledVaultProvider

// SecretProvider resolves policy SecretRef values into concrete secret values.
//
// Providers should fail closed: if a referenced secret is missing, expired, or
// unavailable, Resolve must return an error rather than an empty value.
type SecretProvider interface {
	Resolve(SecretRef) (string, error)
}

func observeSecretResolve(provider string, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	telemetry.ObserveSecretResolve(provider, result)
}
