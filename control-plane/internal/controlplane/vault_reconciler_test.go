package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestReconcileVaultWritesACLPolicyAndJWTRole(t *testing.T) {
	store, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "..", "fixtures", "workloads", "code-agent-vault.yaml")},
		[]string{filepath.Join("..", "..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}

	var policyBody struct {
		Policy string `json:"policy"`
	}
	var roleBody vaultRole
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if got, want := r.Header.Get("X-Vault-Token"), "root"; got != want {
			t.Fatalf("X-Vault-Token = %q, want %q", got, want)
		}

		switch r.URL.Path {
		case "/v1/sys/policies/acl/airlock-code-agent":
			if err := json.NewDecoder(r.Body).Decode(&policyBody); err != nil {
				t.Fatal(err)
			}
		case "/v1/auth/jwt/role/airlock-demo-code-agent":
			if err := json.NewDecoder(r.Body).Decode(&roleBody); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	for workload, compiled := range store.byWorkload {
		if compiled.SecretProvider != nil && compiled.SecretProvider.Vault != nil {
			compiled.SecretProvider.Vault.Address = server.URL
			store.byWorkload[workload] = compiled
		}
	}

	result, err := ReconcileVault(context.Background(), store, VaultReconcileOptions{
		AdminToken: "root",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Policies != 1 || result.Roles != 1 {
		t.Fatalf("result = %+v, want 1 policy and 1 role", result)
	}
	if got, want := strings.Join(requests, ","), "POST /v1/sys/policies/acl/airlock-code-agent,POST /v1/auth/jwt/role/airlock-demo-code-agent"; got != want {
		t.Fatalf("requests = %q, want %q", got, want)
	}
	if !strings.Contains(policyBody.Policy, `path "secret/data/airlock/openai/code-agent"`) {
		t.Fatalf("policy = %q, want secret/data path", policyBody.Policy)
	}
	if got, want := roleBody.BoundSubject, codeAgentIdentity; got != want {
		t.Fatalf("bound_subject = %q, want %q", got, want)
	}
	if got, want := strings.Join(roleBody.BoundAudiences, ","), "vault"; got != want {
		t.Fatalf("bound_audiences = %q, want %q", got, want)
	}
	if got, want := strings.Join(roleBody.TokenPolicies, ","), "airlock-code-agent"; got != want {
		t.Fatalf("token_policies = %q, want %q", got, want)
	}
}

func TestReconcileVaultRequiresAdminToken(t *testing.T) {
	store, err := LoadPolicyStore(
		[]string{filepath.Join("..", "..", "..", "fixtures", "policies", "valid.yaml")},
		[]string{filepath.Join("..", "..", "..", "fixtures", "workloads", "code-agent.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ReconcileVault(context.Background(), store, VaultReconcileOptions{})
	if err == nil {
		t.Fatal("ReconcileVault() error = nil")
	}
	if !strings.Contains(err.Error(), "vault admin token is required") {
		t.Fatalf("error = %q, want admin token error", err)
	}
}
