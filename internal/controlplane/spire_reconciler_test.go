package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestReconcileSPIRECreatesClusterSPIFFEID(t *testing.T) {
	store, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent-vault.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}

	var created clusterSPIFFEID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/apis/spire.spiffe.io/v1alpha1/clusterspiffeids/airlock-code-agent":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/apis/spire.spiffe.io/v1alpha1/clusterspiffeids":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	result, err := ReconcileSPIRE(context.Background(), store, SPIREReconcileOptions{
		Kubernetes: KubernetesPolicySourceOptions{
			APIServerURL: server.URL,
			HTTPClient:   server.Client(),
		},
		ClassName: "spire-system-spire",
		PodLabel:  "app.kubernetes.io/name",
		PodValue:  "airlock-proxy-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ClusterSPIFFEIDs != 1 {
		t.Fatalf("ClusterSPIFFEIDs = %d, want 1", result.ClusterSPIFFEIDs)
	}
	if got, want := created.Metadata.Name, "airlock-code-agent"; got != want {
		t.Fatalf("name = %q, want %q", got, want)
	}
	if got, want := created.Metadata.Labels["airlock.dev/workload-name"], "code-agent"; got != want {
		t.Fatalf("workload label = %q, want %q", got, want)
	}
	if _, ok := created.Metadata.Labels["airlock.dev/policy-name"]; ok {
		t.Fatalf("created ClusterSPIFFEID kept stale policy-name label: %#v", created.Metadata.Labels)
	}
	if got, want := created.Spec.SPIFFEIDTemplate, codeAgentIdentity; got != want {
		t.Fatalf("spiffeIDTemplate = %q, want %q", got, want)
	}
	if got, want := created.Spec.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"], "demo"; got != want {
		t.Fatalf("namespace selector = %q, want %q", got, want)
	}
	if got, want := created.Spec.PodSelector.MatchLabels["app.kubernetes.io/name"], "airlock-proxy-worker"; got != want {
		t.Fatalf("pod selector = %q, want %q", got, want)
	}
}

func TestReconcileSPIREReplacesExistingClusterSPIFFEIDSpec(t *testing.T) {
	store, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent-vault.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}

	var patch []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/apis/spire.spiffe.io/v1alpha1/clusterspiffeids/airlock-code-agent" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got, want := r.Header.Get("Content-Type"), "application/json-patch+json"; got != want {
			t.Fatalf("content-type = %q, want %q", got, want)
		}
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err = ReconcileSPIRE(context.Background(), store, SPIREReconcileOptions{
		Kubernetes: KubernetesPolicySourceOptions{
			APIServerURL: server.URL,
			HTTPClient:   server.Client(),
		},
		ClassName: "spire-system-spire",
		PodLabel:  "airlock.dev/proxy-worker",
		PodValue:  "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(patch) != 2 {
		t.Fatalf("patch operations = %d, want 2", len(patch))
	}
	if got, want := patch[1]["op"], "replace"; got != want {
		t.Fatalf("spec patch op = %q, want %q", got, want)
	}
	spec, ok := patch[1]["value"].(map[string]any)
	if !ok {
		t.Fatalf("spec patch value = %#v, want object", patch[1]["value"])
	}
	podSelector, ok := spec["podSelector"].(map[string]any)
	if !ok {
		t.Fatalf("podSelector = %#v, want object", spec["podSelector"])
	}
	matchLabels, ok := podSelector["matchLabels"].(map[string]any)
	if !ok {
		t.Fatalf("matchLabels = %#v, want object", podSelector["matchLabels"])
	}
	if got, want := matchLabels["airlock.dev/proxy-worker"], "true"; got != want {
		t.Fatalf("pod selector = %q, want %q", got, want)
	}
	if _, ok := matchLabels["app.kubernetes.io/name"]; ok {
		t.Fatalf("pod selector kept stale app.kubernetes.io/name label: %#v", matchLabels)
	}
}

func TestReconcileSPIREGarbageCollectsStaleManagedClusterSPIFFEIDs(t *testing.T) {
	store, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent-vault.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}

	deleted := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/apis/spire.spiffe.io/v1alpha1/clusterspiffeids/airlock-code-agent":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/apis/spire.spiffe.io/v1alpha1/clusterspiffeids":
			if got, want := r.URL.Query().Get("labelSelector"), "airlock.dev/managed-by=airlock-control-plane"; got != want {
				t.Fatalf("labelSelector = %q, want %q", got, want)
			}
			writeTestJSON(t, w, map[string]any{
				"items": []any{
					map[string]any{
						"metadata": map[string]any{"name": "airlock-code-agent"},
					},
					map[string]any{
						"metadata": map[string]any{"name": "airlock-old-policy"},
					},
				},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/apis/spire.spiffe.io/v1alpha1/clusterspiffeids/airlock-old-policy":
			deleted["airlock-old-policy"] = true
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	result, err := ReconcileSPIRE(context.Background(), store, SPIREReconcileOptions{
		Kubernetes: KubernetesPolicySourceOptions{
			APIServerURL: server.URL,
			HTTPClient:   server.Client(),
		},
		GarbageCollect: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ClusterSPIFFEIDs != 1 {
		t.Fatalf("ClusterSPIFFEIDs = %d, want 1", result.ClusterSPIFFEIDs)
	}
	if result.DeletedClusterSPIFFEIDs != 1 {
		t.Fatalf("DeletedClusterSPIFFEIDs = %d, want 1", result.DeletedClusterSPIFFEIDs)
	}
	if !deleted["airlock-old-policy"] {
		t.Fatalf("stale ClusterSPIFFEID was not deleted")
	}
}
