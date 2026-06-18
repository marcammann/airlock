package policy

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

var updateGolden = flag.Bool("update", false, "update compiler golden fixtures")

func TestCompileValidFixture(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent.yaml")
	policies := []AirlockPolicy{loadPolicyFixture(t, "valid.yaml")}

	compiled, err := CompileWorkload(workload, policies)
	require.NoError(t, err)

	assertGoldenJSON(t, "valid.golden.json", compiled)
}

func TestCompileWithSecretProviderResolvesVaultDefaults(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent-vault.yaml")
	policies := []AirlockPolicy{loadPolicyFixture(t, "valid-vault-provider-ref.yaml")}
	provider := loadSecretProviderConfigFixture(t, "default-vault.yaml")

	compiled, err := CompileWorkloadWithSecretProvider(workload, policies, &provider)
	require.NoError(t, err)

	require.NotNil(t, compiled.SecretProvider)
	require.NotNil(t, compiled.SecretProvider.Vault)
	assert.Equal(t, "airlock-demo-code-agent", compiled.SecretProvider.Vault.Role)
	assert.Equal(t, "http://vault.vault.svc.cluster.local:8200", compiled.SecretProvider.Vault.Address)

	ref := compiled.Egress[0].Rewrites[0].ValueFrom
	assert.Equal(t, "secret", ref.Mount)
	assert.Equal(t, "kv-v2", ref.Engine)
}

func TestCompileWithSecretProviderAppliesVaultPathPrefix(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent-vault.yaml")
	policies := []AirlockPolicy{loadPolicyFixture(t, "valid-vault-provider-ref.yaml")}
	provider := loadSecretProviderConfigFixture(t, "default-vault.yaml")
	provider.Spec.Vault.Defaults.PathPrefix = "/prod/"

	compiled, err := CompileWorkloadWithSecretProvider(workload, policies, &provider)
	require.NoError(t, err)

	ref := compiled.Egress[0].Rewrites[0].ValueFrom
	assert.Equal(t, "prod/airlock/openai/code-agent", ref.Path)
}

func TestCompileWithSecretProviderDoesNotMutateInputPolicies(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent-vault.yaml")
	policies := []AirlockPolicy{loadPolicyFixture(t, "valid-vault-provider-ref.yaml")}
	original := mustJSONValue(t, policies)

	firstProvider := loadSecretProviderConfigFixture(t, "default-vault.yaml")
	firstProvider.Spec.Vault.Defaults.PathPrefix = "prod"
	_, err := CompileWorkloadWithSecretProvider(workload, policies, &firstProvider)
	require.NoError(t, err)
	assert.Equal(t, original, mustJSONValue(t, policies))

	secondProvider := loadSecretProviderConfigFixture(t, "default-vault.yaml")
	secondProvider.Spec.Vault.Defaults.PathPrefix = "dev"
	compiled, err := CompileWorkloadWithSecretProvider(workload, policies, &secondProvider)
	require.NoError(t, err)
	assert.Equal(t, original, mustJSONValue(t, policies))
	assert.Equal(t, "dev/airlock/openai/code-agent", compiled.Egress[0].Rewrites[0].ValueFrom.Path)
}

func TestValidateSecretProviderRejectsUnsafeVaultPathPrefix(t *testing.T) {
	provider := loadSecretProviderConfigFixture(t, "default-vault.yaml")
	provider.Spec.Vault.Defaults.PathPrefix = "auth/prod"

	err := ValidateSecretProviderConfig(provider)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pathPrefix cannot target sys/ or auth/")
}

func TestCompileAllowsEmptyEgressAsDenyAllPolicy(t *testing.T) {
	workload := loadWorkloadFixture(t, "deny-all.yaml")
	policies := []AirlockPolicy{loadPolicyFixture(t, "deny-all.yaml")}

	compiled, err := CompileWorkload(workload, policies)
	require.NoError(t, err)
	assert.Empty(t, compiled.Egress)
}

func TestCompileWorkloadRejectsMissingPolicyRef(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent.yaml")

	_, err := CompileWorkload(workload, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "airlock-system/openai-api not found")
}

func TestCompileWorkloadRejectsDuplicateEgressRuleNames(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent.yaml")
	workload.Spec.PolicyRefs = append(workload.Spec.PolicyRefs, PolicyRef{Name: "duplicate-openai-api"})
	policy := loadPolicyFixture(t, "valid.yaml")
	duplicate := policy
	duplicate.Metadata.Name = "duplicate-openai-api"

	_, err := CompileWorkload(workload, []AirlockPolicy{policy, duplicate})
	require.Error(t, err)
	require.Contains(t, err.Error(), `egress rule "openai-api"`)
}

func TestValidateRejectsDuplicateEgressRuleNamesWithinPolicy(t *testing.T) {
	input := loadPolicyFixture(t, "valid.yaml")
	input.Spec.Egress = append(input.Spec.Egress, input.Spec.Egress[0])

	err := Validate(input)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicates egress rule openai-api")
}

func TestCompileNormalizesSchemeAndHost(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent.yaml")
	input := loadPolicyFixture(t, "valid.yaml")
	input.Spec.Egress[0].Scheme = "HTTPS"
	input.Spec.Egress[0].Host = "API.OPENAI.COM"

	compiled, err := CompileWorkload(workload, []AirlockPolicy{input})
	require.NoError(t, err)
	assert.Equal(t, "https", compiled.Egress[0].Scheme)
	assert.Equal(t, "api.openai.com", compiled.Egress[0].Host)
}

func TestNormalizePolicyNormalizesSchemeAndHostWithoutMutatingInput(t *testing.T) {
	input := loadPolicyFixture(t, "valid.yaml")
	input.Spec.Egress[0].Scheme = "HTTPS"
	input.Spec.Egress[0].Host = "API.OPENAI.COM"

	normalized := NormalizePolicy(input)

	assert.Equal(t, "https", normalized.Spec.Egress[0].Scheme)
	assert.Equal(t, "api.openai.com", normalized.Spec.Egress[0].Host)
	assert.Equal(t, "HTTPS", input.Spec.Egress[0].Scheme)
	assert.Equal(t, "API.OPENAI.COM", input.Spec.Egress[0].Host)
}

func TestInvalidFixtures(t *testing.T) {
	tests := map[string]string{
		"invalid-wildcard-secret-path.yaml": "path cannot contain wildcards",
		"invalid-unknown-provider.yaml":     "provider must be one of env, file, vault",
		"invalid-missing-host.yaml":         "host is required",
		"invalid-unsafe-vault-path.yaml":    "path cannot target sys/ or auth/",
	}

	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			err := Validate(loadPolicyFixture(t, name))
			require.Error(t, err)
			require.True(t, IsValidationError(err), "error type = %T", err)
			require.Contains(t, err.Error(), want)
		})
	}
}

func loadPolicyFixture(t *testing.T, name string) AirlockPolicy {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "policies", name))
	require.NoError(t, err)

	var out AirlockPolicy
	require.NoError(t, yaml.Unmarshal(data, &out))
	return out
}

func loadWorkloadFixture(t *testing.T, name string) AirlockWorkload {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "workloads", name))
	require.NoError(t, err)

	var out AirlockWorkload
	require.NoError(t, yaml.Unmarshal(data, &out))
	return out
}

func loadSecretProviderConfigFixture(t *testing.T, name string) SecretProviderConfig {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "secret-provider-configs", name))
	require.NoError(t, err)

	var out SecretProviderConfig
	require.NoError(t, yaml.Unmarshal(data, &out))
	return out
}

func assertGoldenJSON(t *testing.T, name string, value any) {
	t.Helper()

	path := filepath.Join("..", "..", "fixtures", "compiler", name)
	if *updateGolden {
		data, err := json.MarshalIndent(value, "", "  ")
		require.NoError(t, err)
		data = append(data, '\n')
		require.NoError(t, os.WriteFile(path, data, 0o644))
	}
	got := mustJSONValue(t, value)
	want := mustReadJSONFixture(t, path)
	assert.Equal(t, want, got)
}

func mustReadJSONFixture(t *testing.T, path string) any {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var out any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

func mustJSONValue(t *testing.T, value any) any {
	t.Helper()

	data, err := json.Marshal(value)
	require.NoError(t, err)

	var out any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}
