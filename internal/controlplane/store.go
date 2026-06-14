package controlplane

import (
	"fmt"
	"os"
	"sort"

	"github.com/marcammann/airlock/internal/policy"
	"gopkg.in/yaml.v3"
)

type PolicyStore struct {
	byWorkload map[string]policy.CompiledPolicy
	policies   []policy.AirlockPolicy
	workloads  []policy.AirlockWorkload
}

func LoadPolicyStore(policyPaths []string, workloadPaths []string) (*PolicyStore, error) {
	return LoadPolicyStoreWithSecretProviderConfigs(policyPaths, workloadPaths, nil)
}

func LoadPolicyStoreWithSecretProviderConfigs(policyPaths []string, workloadPaths []string, providerConfigPaths []string) (*PolicyStore, error) {
	store := &PolicyStore{byWorkload: map[string]policy.CompiledPolicy{}}
	providerConfigs, err := loadSecretProviderConfigs(providerConfigPaths)
	if err != nil {
		return nil, err
	}

	policies, err := loadPolicies(policyPaths)
	if err != nil {
		return nil, err
	}
	workloads, err := loadWorkloads(workloadPaths)
	if err != nil {
		return nil, err
	}
	store.policies = append([]policy.AirlockPolicy(nil), policies...)
	store.workloads = append([]policy.AirlockWorkload(nil), workloads...)

	for _, workload := range workloads {
		compiled, err := compileWorkload(workload, policies, providerConfigs)
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
	return NewPolicyStoreFromResources(nil, nil, compiledPolicies)
}

func NewPolicyStoreFromResources(policies []policy.AirlockPolicy, workloads []policy.AirlockWorkload, compiledPolicies []policy.CompiledPolicy) (*PolicyStore, error) {
	store := &PolicyStore{
		byWorkload: map[string]policy.CompiledPolicy{},
		policies:   append([]policy.AirlockPolicy(nil), policies...),
		workloads:  append([]policy.AirlockWorkload(nil), workloads...),
	}
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

func (s *PolicyStore) AirlockPolicies() []policy.AirlockPolicy {
	out := append([]policy.AirlockPolicy(nil), s.policies...)
	sort.Slice(out, func(i int, j int) bool {
		if out[i].Metadata.Namespace == out[j].Metadata.Namespace {
			return out[i].Metadata.Name < out[j].Metadata.Name
		}
		return out[i].Metadata.Namespace < out[j].Metadata.Namespace
	})
	return out
}

func (s *PolicyStore) AirlockWorkloads() []policy.AirlockWorkload {
	out := append([]policy.AirlockWorkload(nil), s.workloads...)
	sort.Slice(out, func(i int, j int) bool {
		if out[i].Metadata.Namespace == out[j].Metadata.Namespace {
			return out[i].Metadata.Name < out[j].Metadata.Name
		}
		return out[i].Metadata.Namespace < out[j].Metadata.Namespace
	})
	return out
}

func loadPolicies(paths []string) ([]policy.AirlockPolicy, error) {
	policies := make([]policy.AirlockPolicy, 0, len(paths))
	for _, path := range paths {
		input, err := loadPolicy(path)
		if err != nil {
			return nil, err
		}
		policies = append(policies, input)
	}
	return policies, nil
}

func loadPolicy(path string) (policy.AirlockPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policy.AirlockPolicy{}, fmt.Errorf("read policy %q: %w", path, err)
	}

	var input policy.AirlockPolicy
	if err := yaml.Unmarshal(data, &input); err != nil {
		return policy.AirlockPolicy{}, fmt.Errorf("parse policy %q: %w", path, err)
	}
	return input, nil
}

func loadWorkloads(paths []string) ([]policy.AirlockWorkload, error) {
	workloads := make([]policy.AirlockWorkload, 0, len(paths))
	for _, path := range paths {
		input, err := loadWorkload(path)
		if err != nil {
			return nil, err
		}
		workloads = append(workloads, input)
	}
	return workloads, nil
}

func loadWorkload(path string) (policy.AirlockWorkload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policy.AirlockWorkload{}, fmt.Errorf("read workload %q: %w", path, err)
	}

	var input policy.AirlockWorkload
	if err := yaml.Unmarshal(data, &input); err != nil {
		return policy.AirlockWorkload{}, fmt.Errorf("parse workload %q: %w", path, err)
	}
	if err := policy.ValidateWorkload(input); err != nil {
		return policy.AirlockWorkload{}, fmt.Errorf("validate workload %q: %w", path, err)
	}
	return input, nil
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

func compileWorkload(input policy.AirlockWorkload, policies []policy.AirlockPolicy, providerConfigs map[string]policy.SecretProviderConfig) (policy.CompiledPolicy, error) {
	providerConfig, err := resolveSecretProviderConfig(input, providerConfigs)
	if err != nil {
		return policy.CompiledPolicy{}, fmt.Errorf("resolve secret provider for workload %s/%s: %w", input.Metadata.Namespace, input.Metadata.Name, err)
	}
	compiled, err := policy.CompileWorkloadWithSecretProvider(input, policies, providerConfig)
	if err != nil {
		return policy.CompiledPolicy{}, fmt.Errorf("compile workload %s/%s: %w", input.Metadata.Namespace, input.Metadata.Name, err)
	}
	return compiled, nil
}

func resolveSecretProviderConfig(input policy.AirlockWorkload, configs map[string]policy.SecretProviderConfig) (*policy.SecretProviderConfig, error) {
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
