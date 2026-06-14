package proxyworker

import (
	"context"
)

func NewSecretProviderForPolicy(ctx context.Context, policy CompiledPolicy, spiffeSocket string) (SecretProvider, error) {
	if !PolicyHasVaultSecretRefs(policy) {
		return EnvFileSecretProvider{}, nil
	}
	provider, err := NewVaultSecretProvider(ctx, policy, spiffeSocket)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

func PolicyHasVaultSecretRefs(policy CompiledPolicy) bool {
	for _, rule := range policy.Egress {
		for _, rewrite := range rule.Rewrites {
			if rewrite.ValueFrom.Provider == "vault" {
				return true
			}
		}
	}
	return false
}

func vaultSecretRefs(policy CompiledPolicy) []SecretRef {
	var refs []SecretRef
	seen := map[vaultSecretKey]bool{}
	for _, rule := range policy.Egress {
		for _, rewrite := range rule.Rewrites {
			ref := rewrite.ValueFrom
			if ref.Provider != "vault" {
				continue
			}
			key := vaultSecretKey{Mount: ref.Mount, Path: ref.Path, Key: ref.Key}
			if !seen[key] {
				refs = append(refs, ref)
				seen[key] = true
			}
		}
	}
	return refs
}
