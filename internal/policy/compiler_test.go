package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCompileValidFixture(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent.yaml")
	policies := []AirlockPolicy{loadPolicyFixture(t, "valid.yaml")}

	compiled, err := CompileWorkload(workload, policies)
	if err != nil {
		t.Fatalf("CompileWorkload() error = %v", err)
	}

	got := mustJSONValue(t, compiled)
	want := mustReadJSONFixture(t, "valid.json")
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("compiled policy mismatch\ngot:\n%s\nwant:\n%s", gotJSON, wantJSON)
	}
}

func TestCompileWithSecretProviderResolvesVaultDefaults(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent-vault.yaml")
	policies := []AirlockPolicy{loadPolicyFixture(t, "valid-vault-provider-ref.yaml")}
	provider := loadSecretProviderConfigFixture(t, "default-vault.yaml")

	compiled, err := CompileWorkloadWithSecretProvider(workload, policies, &provider)
	if err != nil {
		t.Fatalf("CompileWorkloadWithSecretProvider() error = %v", err)
	}

	if compiled.SecretProvider == nil || compiled.SecretProvider.Vault == nil {
		t.Fatal("compiled secret provider is nil")
	}
	if got, want := compiled.SecretProvider.Vault.Role, "airlock-demo-code-agent"; got != want {
		t.Fatalf("role = %q, want %q", got, want)
	}
	if got, want := compiled.SecretProvider.Vault.Address, "http://vault.vault.svc.cluster.local:8200"; got != want {
		t.Fatalf("address = %q, want %q", got, want)
	}

	ref := compiled.Egress[0].Rewrites[0].ValueFrom
	if got, want := ref.Mount, "secret"; got != want {
		t.Fatalf("resolved mount = %q, want %q", got, want)
	}
	if got, want := ref.Engine, "kv-v2"; got != want {
		t.Fatalf("resolved engine = %q, want %q", got, want)
	}
}

func TestCompileWithSecretProviderAppliesVaultPathPrefix(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent-vault.yaml")
	policies := []AirlockPolicy{loadPolicyFixture(t, "valid-vault-provider-ref.yaml")}
	provider := loadSecretProviderConfigFixture(t, "default-vault.yaml")
	provider.Spec.Vault.Defaults.PathPrefix = "/prod/"

	compiled, err := CompileWorkloadWithSecretProvider(workload, policies, &provider)
	if err != nil {
		t.Fatalf("CompileWorkloadWithSecretProvider() error = %v", err)
	}

	ref := compiled.Egress[0].Rewrites[0].ValueFrom
	if got, want := ref.Path, "prod/airlock/openai/code-agent"; got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestValidateSecretProviderRejectsUnsafeVaultPathPrefix(t *testing.T) {
	provider := loadSecretProviderConfigFixture(t, "default-vault.yaml")
	provider.Spec.Vault.Defaults.PathPrefix = "auth/prod"

	err := ValidateSecretProviderConfig(provider)
	if err == nil {
		t.Fatal("ValidateSecretProviderConfig() error = nil")
	}
	if !strings.Contains(err.Error(), "pathPrefix cannot target sys/ or auth/") {
		t.Fatalf("ValidateSecretProviderConfig() error = %q, want unsafe pathPrefix", err.Error())
	}
}

func TestCompileAllowsEmptyEgressAsDenyAllPolicy(t *testing.T) {
	workload := loadWorkloadFixture(t, "deny-all.yaml")
	policies := []AirlockPolicy{loadPolicyFixture(t, "deny-all.yaml")}

	compiled, err := CompileWorkload(workload, policies)
	if err != nil {
		t.Fatalf("CompileWorkload() error = %v", err)
	}
	if len(compiled.Egress) != 0 {
		t.Fatalf("compiled egress length = %d, want 0", len(compiled.Egress))
	}
}

func TestCompileWorkloadRejectsMissingPolicyRef(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent.yaml")

	_, err := CompileWorkload(workload, nil)
	if err == nil {
		t.Fatal("CompileWorkload() error = nil")
	}
	if !strings.Contains(err.Error(), "airlock-system/openai-api not found") {
		t.Fatalf("CompileWorkload() error = %q, want missing policy ref", err.Error())
	}
}

func TestCompileWorkloadRejectsDuplicateEgressRuleNames(t *testing.T) {
	workload := loadWorkloadFixture(t, "code-agent.yaml")
	workload.Spec.PolicyRefs = append(workload.Spec.PolicyRefs, PolicyRef{Name: "duplicate-openai-api"})
	policy := loadPolicyFixture(t, "valid.yaml")
	duplicate := policy
	duplicate.Metadata.Name = "duplicate-openai-api"

	_, err := CompileWorkload(workload, []AirlockPolicy{policy, duplicate})
	if err == nil {
		t.Fatal("CompileWorkload() error = nil")
	}
	if !strings.Contains(err.Error(), `egress rule "openai-api"`) {
		t.Fatalf("CompileWorkload() error = %q, want duplicate egress rule", err.Error())
	}
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
			if err == nil {
				t.Fatal("Validate() error = nil")
			}
			if !IsValidationError(err) {
				t.Fatalf("Validate() error type = %T, want ValidationError", err)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), want)
			}
		})
	}
}

func loadPolicyFixture(t *testing.T, name string) AirlockPolicy {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "policies", name))
	if err != nil {
		t.Fatal(err)
	}

	var out AirlockPolicy
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func loadWorkloadFixture(t *testing.T, name string) AirlockWorkload {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "workloads", name))
	if err != nil {
		t.Fatal(err)
	}

	var out AirlockWorkload
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func loadSecretProviderConfigFixture(t *testing.T, name string) SecretProviderConfig {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "secret-provider-configs", name))
	if err != nil {
		t.Fatal(err)
	}

	var out SecretProviderConfig
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mustReadJSONFixture(t *testing.T, name string) any {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "compiled", name))
	if err != nil {
		t.Fatal(err)
	}

	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mustJSONValue(t *testing.T, value any) any {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
