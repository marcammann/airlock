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
	policy := loadPolicyFixture(t, "valid.yaml")

	compiled, err := Compile(policy)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
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
	policy := loadPolicyFixture(t, "valid-vault-provider-ref.yaml")
	provider := loadSecretProviderConfigFixture(t, "default-vault.yaml")

	compiled, err := CompileWithSecretProvider(policy, &provider)
	if err != nil {
		t.Fatalf("CompileWithSecretProvider() error = %v", err)
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

func TestCompileAllowsEmptyEgressAsDenyAllPolicy(t *testing.T) {
	input := AirlockPolicy{
		APIVersion: APIVersion,
		Kind:       "AirlockPolicy",
		Metadata: Metadata{
			Name: "deny-all",
		},
		Spec: Spec{
			Workload: WorkloadIdentity{
				SPIFFEID: "spiffe://airlock.local/compose/opencode/component/airlock-proxy-worker",
			},
			Egress: []EgressRule{},
		},
	}

	compiled, err := Compile(input)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if len(compiled.Egress) != 0 {
		t.Fatalf("compiled egress length = %d, want 0", len(compiled.Egress))
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
			_, err := Compile(loadPolicyFixture(t, name))
			if err == nil {
				t.Fatal("Compile() error = nil")
			}
			if !IsValidationError(err) {
				t.Fatalf("Compile() error type = %T, want ValidationError", err)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("Compile() error = %q, want substring %q", err.Error(), want)
			}
		})
	}
}

func loadPolicyFixture(t *testing.T, name string) AirlockPolicy {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "fixtures", "policies", name))
	if err != nil {
		t.Fatal(err)
	}

	var out AirlockPolicy
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func loadSecretProviderConfigFixture(t *testing.T, name string) SecretProviderConfig {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "fixtures", "secret-provider-configs", name))
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

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "fixtures", "compiled", name))
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
