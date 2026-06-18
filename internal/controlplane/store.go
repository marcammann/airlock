package controlplane

import (
	controlstore "github.com/marcammann/airlock/internal/controlplane/store"
	"github.com/marcammann/airlock/internal/policy"
)

// PolicyStore indexes compiled policies by workload identity.
type PolicyStore = controlstore.PolicyStore

// LoadPolicyStore loads policies and workloads from files.
func LoadPolicyStore(policyPaths []string, workloadPaths []string) (*PolicyStore, error) {
	return controlstore.LoadPolicyStore(policyPaths, workloadPaths)
}

// LoadPolicyStoreWithSecretProviderConfigs loads files and provider configs.
func LoadPolicyStoreWithSecretProviderConfigs(policyPaths []string, workloadPaths []string, providerConfigPaths []string) (*PolicyStore, error) {
	return controlstore.LoadPolicyStoreWithSecretProviderConfigs(policyPaths, workloadPaths, providerConfigPaths)
}

// NewPolicyStoreFromCompiled creates a policy store from compiled policies.
func NewPolicyStoreFromCompiled(compiledPolicies []policy.CompiledPolicy) (*PolicyStore, error) {
	return controlstore.NewPolicyStoreFromCompiled(compiledPolicies)
}

// NewPolicyStoreFromResources creates a policy store from source and compiled resources.
func NewPolicyStoreFromResources(policies []policy.AirlockPolicy, workloads []policy.AirlockWorkload, compiledPolicies []policy.CompiledPolicy) (*PolicyStore, error) {
	return controlstore.NewPolicyStoreFromResources(policies, workloads, compiledPolicies)
}

func loadPolicies(paths []string) ([]policy.AirlockPolicy, error) {
	return controlstore.LoadPolicies(paths)
}

func resolveSecretProviderConfig(input policy.AirlockWorkload, configs map[string]policy.SecretProviderConfig) (*policy.SecretProviderConfig, error) {
	return controlstore.ResolveSecretProviderConfig(input, configs)
}

func providerConfigKey(namespace string, name string) string {
	return controlstore.ProviderConfigKey(namespace, name)
}
