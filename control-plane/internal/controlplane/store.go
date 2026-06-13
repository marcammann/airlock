package controlplane

import (
	"fmt"
	"os"
	"sort"

	"github.com/marc/airlock/control-plane/internal/policy"
	"gopkg.in/yaml.v3"
)

type PolicyStore struct {
	byWorkload map[string]policy.CompiledPolicy
}

func LoadPolicyStore(paths []string) (*PolicyStore, error) {
	return LoadPolicyStoreWithSecretProviderConfigs(paths, nil)
}

func LoadPolicyStoreWithSecretProviderConfigs(paths []string, providerConfigPaths []string) (*PolicyStore, error) {
	store := &PolicyStore{byWorkload: map[string]policy.CompiledPolicy{}}
	providerConfigs, err := loadSecretProviderConfigs(providerConfigPaths)
	if err != nil {
		return nil, err
	}

	for _, path := range paths {
		compiled, err := loadPolicy(path, providerConfigs)
		if err != nil {
			return nil, err
		}

		key := compiled.Workload.SPIFFEID
		if key == "" {
			return nil, fmt.Errorf("compiled policy %q has empty workload identity", compiled.PolicyName)
		}
		if existing, ok := store.byWorkload[key]; ok {
			return nil, fmt.Errorf("workload identity %q is already mapped to policy %q", key, existing.PolicyName)
		}
		store.byWorkload[key] = compiled
	}

	return store, nil
}

func NewPolicyStoreFromCompiled(compiledPolicies []policy.CompiledPolicy) (*PolicyStore, error) {
	store := &PolicyStore{byWorkload: map[string]policy.CompiledPolicy{}}
	for _, compiled := range compiledPolicies {
		key := compiled.Workload.SPIFFEID
		if key == "" {
			return nil, fmt.Errorf("compiled policy %q has empty workload identity", compiled.PolicyName)
		}
		if existing, ok := store.byWorkload[key]; ok {
			return nil, fmt.Errorf("workload identity %q is already mapped to policy %q", key, existing.PolicyName)
		}
		store.byWorkload[key] = compiled
	}
	return store, nil
}

func (s *PolicyStore) Get(workloadIdentity string) (policy.CompiledPolicy, bool) {
	compiled, ok := s.byWorkload[workloadIdentity]
	return compiled, ok
}

func (s *PolicyStore) Len() int {
	return len(s.byWorkload)
}

func (s *PolicyStore) Policies() []policy.CompiledPolicy {
	out := make([]policy.CompiledPolicy, 0, len(s.byWorkload))
	for _, compiled := range s.byWorkload {
		out = append(out, compiled)
	}
	sort.Slice(out, func(i int, j int) bool {
		if out[i].PolicyName == out[j].PolicyName {
			return out[i].Workload.SPIFFEID < out[j].Workload.SPIFFEID
		}
		return out[i].PolicyName < out[j].PolicyName
	})
	return out
}

func loadPolicy(path string, providerConfigs map[string]policy.SecretProviderConfig) (policy.CompiledPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policy.CompiledPolicy{}, fmt.Errorf("read policy %q: %w", path, err)
	}

	var input policy.AirlockPolicy
	if err := yaml.Unmarshal(data, &input); err != nil {
		return policy.CompiledPolicy{}, fmt.Errorf("parse policy %q: %w", path, err)
	}

	providerConfig, err := resolveSecretProviderConfig(input, providerConfigs)
	if err != nil {
		return policy.CompiledPolicy{}, fmt.Errorf("resolve secret provider for policy %q: %w", path, err)
	}

	compiled, err := policy.CompileWithSecretProvider(input, providerConfig)
	if err != nil {
		return policy.CompiledPolicy{}, fmt.Errorf("compile policy %q: %w", path, err)
	}

	return compiled, nil
}

func loadSecretProviderConfigs(paths []string) (map[string]policy.SecretProviderConfig, error) {
	out := map[string]policy.SecretProviderConfig{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read secret provider config %q: %w", path, err)
		}
		var input policy.SecretProviderConfig
		if err := yaml.Unmarshal(data, &input); err != nil {
			return nil, fmt.Errorf("parse secret provider config %q: %w", path, err)
		}
		if err := policy.ValidateSecretProviderConfig(input); err != nil {
			return nil, fmt.Errorf("validate secret provider config %q: %w", path, err)
		}
		key := providerConfigKey(input.Metadata.Namespace, input.Metadata.Name)
		if existing, ok := out[key]; ok {
			return nil, fmt.Errorf("secret provider config %q duplicates %q", input.Metadata.Name, existing.Metadata.Name)
		}
		out[key] = input
	}
	return out, nil
}

func resolveSecretProviderConfig(input policy.AirlockPolicy, configs map[string]policy.SecretProviderConfig) (*policy.SecretProviderConfig, error) {
	ref := input.Spec.SecretProviderRef
	if ref.Name == "" {
		return nil, nil
	}
	namespace := ref.Namespace
	if namespace == "" {
		namespace = input.Metadata.Namespace
	}
	key := providerConfigKey(namespace, ref.Name)
	config, ok := configs[key]
	if !ok {
		return nil, fmt.Errorf("secretProviderRef %s/%s not found", namespace, ref.Name)
	}
	return &config, nil
}

func providerConfigKey(namespace string, name string) string {
	return namespace + "/" + name
}
