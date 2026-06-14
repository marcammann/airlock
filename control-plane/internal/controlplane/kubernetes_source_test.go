package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marc/airlock/control-plane/internal/policy"
)

func TestLoadPolicyStoreFromKubernetes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apis/airlock.dev/v1alpha1/namespaces/airlock-system/secretproviderconfigs":
			writeTestJSON(t, w, map[string]any{"items": []any{defaultVaultProviderConfig()}})
		case "/apis/airlock.dev/v1alpha1/namespaces/airlock-system/airlockpolicies":
			writeTestJSON(t, w, map[string]any{"items": []any{codeAgentPolicy()}})
		case "/apis/airlock.dev/v1alpha1/namespaces/airlock-system/airlockworkloads":
			writeTestJSON(t, w, map[string]any{"items": []any{codeAgentWorkload()}})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	store, updates, err := LoadPolicyStoreFromKubernetes(context.Background(), KubernetesPolicySourceOptions{
		Namespace:    "airlock-system",
		APIServerURL: server.URL,
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.Len() != 1 {
		t.Fatalf("store.Len() = %d, want 1", store.Len())
	}
	compiled, ok := store.Get(codeAgentIdentity)
	if !ok {
		t.Fatal("compiled code-agent policy not found")
	}
	if got, want := compiled.SecretProvider.Vault.Role, "airlock-demo-code-agent"; got != want {
		t.Fatalf("role = %q, want %q", got, want)
	}
	if got, want := compiled.Egress[0].Rewrites[0].ValueFrom.Mount, "secret"; got != want {
		t.Fatalf("mount = %q, want %q", got, want)
	}
	if got, want := compiled.Egress[0].Rewrites[0].ValueFrom.Path, "prod/airlock/openai/code-agent"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if len(updates) != 1 || updates[0].Status.PolicyHash == "" {
		t.Fatalf("updates = %+v, want one status update with policy hash", updates)
	}
}

func TestPatchAirlockWorkloadStatus(t *testing.T) {
	var patched map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPatch; got != want {
			t.Fatalf("method = %q, want %q", got, want)
		}
		if got, want := r.URL.Path, "/apis/airlock.dev/v1alpha1/namespaces/airlock-system/airlockworkloads/code-agent/status"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/merge-patch+json") {
			t.Fatalf("content-type = %q, want merge patch", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	input := mustAirlockWorkload(t, codeAgentWorkload())
	err := PatchAirlockWorkloadStatus(context.Background(), KubernetesPolicySourceOptions{
		Namespace:    "airlock-system",
		APIServerURL: server.URL,
		HTTPClient:   server.Client(),
	}, input, policy.Status{
		ObservedGeneration: input.Metadata.Generation,
		PolicyHash:         "abc123",
		Conditions:         []policy.StatusCondition{{Type: "Ready", Status: "True"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, ok := patched["status"].(map[string]any)
	if !ok {
		t.Fatalf("patched = %#v, want status object", patched)
	}
	if got, want := status["observedGeneration"], float64(4); got != want {
		t.Fatalf("observedGeneration = %#v, want %#v", got, want)
	}
}

func defaultVaultProviderConfig() map[string]any {
	return map[string]any{
		"apiVersion": "airlock.dev/v1alpha1",
		"kind":       "SecretProviderConfig",
		"metadata": map[string]any{
			"name":      "default-vault",
			"namespace": "airlock-system",
		},
		"spec": map[string]any{
			"provider": "vault",
			"vault": map[string]any{
				"address": "http://vault.vault.svc.cluster.local:8200",
				"auth": map[string]any{
					"method":   "spiffe-jwt",
					"mount":    "jwt",
					"audience": "vault",
				},
				"defaults": map[string]any{
					"engine":     "kv-v2",
					"mount":      "secret",
					"pathPrefix": "prod",
				},
			},
		},
	}
}

func codeAgentPolicy() map[string]any {
	return map[string]any{
		"apiVersion": "airlock.dev/v1alpha1",
		"kind":       "AirlockPolicy",
		"metadata": map[string]any{
			"name":       "code-agent",
			"namespace":  "airlock-system",
			"generation": float64(4),
		},
		"spec": map[string]any{
			"egress": []any{map[string]any{
				"name":   "echo-upstream",
				"scheme": "http",
				"host":   "echo-upstream.demo.svc.cluster.local",
				"port":   float64(8080),
				"rewrites": []any{map[string]any{
					"target":        "header",
					"name":          "Authorization",
					"valueTemplate": "Bearer {{secret}}",
					"valueFrom": map[string]any{
						"provider": "vault",
						"name":     "test-token",
						"path":     "airlock/openai/code-agent",
						"key":      "api_key",
					},
				}},
			}},
		},
	}
}

func codeAgentWorkload() map[string]any {
	return map[string]any{
		"apiVersion": "airlock.dev/v1alpha1",
		"kind":       "AirlockWorkload",
		"metadata": map[string]any{
			"name":       "code-agent",
			"namespace":  "airlock-system",
			"generation": float64(4),
		},
		"spec": map[string]any{
			"secretProviderRef": map[string]any{
				"name": "default-vault",
			},
			"workload": map[string]any{
				"spiffeId":       codeAgentIdentity,
				"namespace":      "demo",
				"serviceAccount": "code-agent",
			},
			"policyRefs": []any{map[string]any{"name": "code-agent"}},
		},
	}
}

func mustAirlockWorkload(t *testing.T, input map[string]any) policy.AirlockWorkload {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var p policy.AirlockWorkload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}
