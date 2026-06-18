package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	"github.com/marcammann/airlock/internal/policy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLoadPolicyStoreFromKubernetesClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := airlockv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			ptrTo(mustSecretProviderConfig(t, defaultVaultProviderConfig())),
			ptrTo(mustAirlockPolicy(t, codeAgentPolicy())),
			ptrTo(mustAirlockWorkload(t, codeAgentWorkload())),
		).
		Build()

	store, updates, err := LoadPolicyStoreFromKubernetesClient(context.Background(), kube, "airlock-system")
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
	if got, want := compiled.Egress[0].Rewrites[0].ValueFrom.Path, "prod/airlock/openai/code-agent"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if len(updates) != 1 || updates[0].Status.PolicyHash == "" {
		t.Fatalf("updates = %+v, want one status update with policy hash", updates)
	}
}

func TestKubernetesClientRejectsOversizedList(t *testing.T) {
	// The fake controller-runtime client is in-memory and never goes through
	// the HTTP transport, so we test the transport wrapper directly to verify
	// that oversized Kubernetes API responses are rejected.
	oversized := strings.Repeat("x", 5<<20) // 5 MiB, exceeds the 4 MiB limit
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(oversized))
	}))
	defer srv.Close()

	transport := &limitedResponseTransportForTest{base: http.DefaultTransport, limit: 4 << 20}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if err == nil {
		t.Fatal("ReadAll() error = nil, want oversized body rejection")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %q, want 'exceeds'", err)
	}
}

// limitedResponseTransportForTest mirrors the production limitedResponseTransport
// for unit testing without importing the main package.
type limitedResponseTransportForTest struct {
	base  http.RoundTripper
	limit int64
}

func (t *limitedResponseTransportForTest) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	resp.Body = &limitedReadCloserForTest{r: io.LimitReader(resp.Body, t.limit+1), limit: t.limit}
	return resp, nil
}

type limitedReadCloserForTest struct {
	r     io.Reader
	limit int64
	read  int64
}

func (l *limitedReadCloserForTest) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.read += int64(n)
	if err == nil && l.read > l.limit {
		return n, fmt.Errorf("kubernetes response body exceeds %d bytes", l.limit)
	}
	return n, err
}

func (l *limitedReadCloserForTest) Close() error {
	if c, ok := l.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func TestPatchAirlockWorkloadStatusWithClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := airlockv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	workload := mustAirlockWorkload(t, codeAgentWorkload())
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&policy.AirlockWorkload{}).
		WithObjects(ptrTo(workload)).
		Build()

	err := PatchAirlockWorkloadStatusWithClient(context.Background(), kube, workload, policy.Status{
		ObservedGeneration: workload.Metadata.Generation,
		PolicyHash:         "abc123",
		Conditions:         []policy.StatusCondition{{Type: "Ready", Status: "True"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var out policy.AirlockWorkload
	if err := kube.Get(context.Background(), ctrlclient.ObjectKey{Namespace: workload.Metadata.Namespace, Name: workload.Metadata.Name}, &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.Status.PolicyHash, "abc123"; got != want {
		t.Fatalf("policyHash = %q, want %q", got, want)
	}
	if len(out.Status.Conditions) != 1 || out.Status.Conditions[0].Status != "True" {
		t.Fatalf("conditions = %+v, want Ready=True", out.Status.Conditions)
	}
}

func TestPatchAirlockWorkloadStatusWithClientRetriesConflict(t *testing.T) {
	assertStatusPatchRetriesConflict(t)
}

func TestReconcilerRetriesOnConflict(t *testing.T) {
	assertStatusPatchRetriesConflict(t)
}

func assertStatusPatchRetriesConflict(t *testing.T) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := airlockv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	workload := mustAirlockWorkload(t, codeAgentWorkload())
	base := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&policy.AirlockWorkload{}).
		WithObjects(ptrTo(workload)).
		Build()
	kube := &conflictOnceStatusClient{Client: base}

	err := PatchAirlockWorkloadStatusWithClient(context.Background(), kube, workload, policy.Status{
		ObservedGeneration: workload.Metadata.Generation,
		PolicyHash:         "retry-hash",
		Conditions:         []policy.StatusCondition{{Type: "Ready", Status: "True"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if kube.patchAttempts != 2 {
		t.Fatalf("patchAttempts = %d, want conflict then retry success", kube.patchAttempts)
	}

	var out policy.AirlockWorkload
	if err := kube.Get(context.Background(), ctrlclient.ObjectKey{Namespace: workload.Metadata.Namespace, Name: workload.Metadata.Name}, &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.Status.PolicyHash, "retry-hash"; got != want {
		t.Fatalf("policyHash = %q, want %q", got, want)
	}
}

func TestKubernetesPolicySourceDropsInvalidPolicies(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := airlockv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	valid := codeAgentPolicy()
	invalid := codeAgentPolicy()
	invalid["metadata"].(map[string]any)["name"] = "invalid"
	delete(invalid["spec"].(map[string]any)["egress"].([]any)[0].(map[string]any), "host")
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			ptrTo(mustSecretProviderConfig(t, defaultVaultProviderConfig())),
			ptrTo(mustAirlockPolicy(t, valid)),
			ptrTo(mustAirlockPolicy(t, invalid)),
			ptrTo(mustAirlockWorkload(t, codeAgentWorkload())),
		).
		Build()

	store, _, err := LoadPolicyStoreFromKubernetesClient(context.Background(), kube, "airlock-system")
	if err != nil {
		t.Fatal(err)
	}
	policies := store.AirlockPolicies()
	if len(policies) != 1 || policies[0].Metadata.Name != "code-agent" {
		t.Fatalf("policies = %+v, want only valid code-agent policy", policies)
	}
}

type conflictOnceStatusClient struct {
	ctrlclient.Client
	patchAttempts int
}

func (c *conflictOnceStatusClient) Status() ctrlclient.SubResourceWriter {
	return &conflictOnceStatusWriter{client: c, delegate: c.Client.Status()}
}

type conflictOnceStatusWriter struct {
	client   *conflictOnceStatusClient
	delegate ctrlclient.SubResourceWriter
}

func (w *conflictOnceStatusWriter) Create(ctx context.Context, obj ctrlclient.Object, subResource ctrlclient.Object, opts ...ctrlclient.SubResourceCreateOption) error {
	return w.delegate.Create(ctx, obj, subResource, opts...)
}

func (w *conflictOnceStatusWriter) Update(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.SubResourceUpdateOption) error {
	return w.delegate.Update(ctx, obj, opts...)
}

func (w *conflictOnceStatusWriter) Patch(ctx context.Context, obj ctrlclient.Object, patch ctrlclient.Patch, opts ...ctrlclient.SubResourcePatchOption) error {
	w.client.patchAttempts++
	if w.client.patchAttempts == 1 {
		return apierrors.NewConflict(schema.GroupResource{Group: "airlock.dev", Resource: "airlockworkloads"}, obj.GetName(), fmt.Errorf("stale resourceVersion"))
	}
	return w.delegate.Patch(ctx, obj, patch, opts...)
}

func (w *conflictOnceStatusWriter) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...ctrlclient.SubResourceApplyOption) error {
	return w.delegate.Apply(ctx, obj, opts...)
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

func mustAirlockPolicy(t *testing.T, input map[string]any) policy.AirlockPolicy {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var p policy.AirlockPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustSecretProviderConfig(t *testing.T, input map[string]any) policy.SecretProviderConfig {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var p policy.SecretProviderConfig
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func ptrTo[T any](value T) *T {
	return &value
}
