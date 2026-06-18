package controlplane

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marcammann/airlock/internal/policy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconcileSPIRECreatesClusterSPIFFEID(t *testing.T) {
	store := mustSPIREPolicyStore(t)
	kube := newSPIREFakeClient(t)

	result, err := ReconcileSPIRE(context.Background(), store, SPIREReconcileOptions{
		Client:    kube,
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

	created := newClusterSPIFFEIDUnstructured()
	if err := kube.Get(context.Background(), ctrlclient.ObjectKey{Name: "airlock-demo-code-agent"}, created); err != nil {
		t.Fatal(err)
	}
	if got, want := created.GetLabels()["airlock.dev/workload-name"], "code-agent"; got != want {
		t.Fatalf("workload label = %q, want %q", got, want)
	}
	if got, _, _ := unstructured.NestedString(created.Object, "spec", "spiffeIDTemplate"); got != codeAgentIdentity {
		t.Fatalf("spiffeIDTemplate = %q, want %q", got, codeAgentIdentity)
	}
	if got, _, _ := unstructured.NestedString(created.Object, "spec", "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); got != "demo" {
		t.Fatalf("namespace selector = %q, want demo", got)
	}
}

func TestReconcileSPIREIsIdempotent(t *testing.T) {
	store := mustSPIREPolicyStore(t)
	kube := newSPIREFakeClient(t)
	opts := SPIREReconcileOptions{
		Client:    kube,
		ClassName: "spire-system-spire",
		PodLabel:  "app.kubernetes.io/name",
		PodValue:  "airlock-proxy-worker",
	}

	first, err := ReconcileSPIRE(context.Background(), store, opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReconcileSPIRE(context.Background(), store, opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.ClusterSPIFFEIDs != 1 || second.ClusterSPIFFEIDs != 1 {
		t.Fatalf("results = first %+v second %+v, want one ClusterSPIFFEID each run", first, second)
	}

	updated := newClusterSPIFFEIDUnstructured()
	if err := kube.Get(context.Background(), ctrlclient.ObjectKey{Name: "airlock-demo-code-agent"}, updated); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := unstructured.NestedString(updated.Object, "spec", "spiffeIDTemplate"); got != codeAgentIdentity {
		t.Fatalf("spiffeIDTemplate = %q, want %q", got, codeAgentIdentity)
	}
	if got, _, _ := unstructured.NestedString(updated.Object, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name"); got != "airlock-proxy-worker" {
		t.Fatalf("pod selector = %q, want airlock-proxy-worker", got)
	}
}

func TestReconcileSPIREReplacesExistingClusterSPIFFEIDSpec(t *testing.T) {
	store := mustSPIREPolicyStore(t)
	existing := newClusterSPIFFEIDUnstructured()
	existing.SetName("airlock-demo-code-agent")
	existing.SetLabels(map[string]string{
		"airlock.dev/managed-by":  "airlock-control-plane",
		"airlock.dev/policy-name": "stale",
	})
	existing.Object["spec"] = map[string]any{
		"spiffeIDTemplate": "stale",
		"podSelector": map[string]any{
			"matchLabels": map[string]any{"stale": "true"},
		},
	}
	kube := newSPIREFakeClient(t, existing)

	_, err := ReconcileSPIRE(context.Background(), store, SPIREReconcileOptions{
		Client:   kube,
		PodLabel: "airlock.dev/proxy-worker",
		PodValue: "true",
	})
	if err != nil {
		t.Fatal(err)
	}

	updated := newClusterSPIFFEIDUnstructured()
	if err := kube.Get(context.Background(), ctrlclient.ObjectKey{Name: "airlock-demo-code-agent"}, updated); err != nil {
		t.Fatal(err)
	}
	if _, ok := updated.GetLabels()["airlock.dev/policy-name"]; ok {
		t.Fatalf("updated ClusterSPIFFEID kept stale policy-name label: %#v", updated.GetLabels())
	}
	if got, _, _ := unstructured.NestedString(updated.Object, "spec", "podSelector", "matchLabels", "airlock.dev/proxy-worker"); got != "true" {
		t.Fatalf("pod selector = %q, want true", got)
	}
	if _, ok, _ := unstructured.NestedString(updated.Object, "spec", "podSelector", "matchLabels", "stale"); ok {
		t.Fatalf("pod selector kept stale label: %#v", updated.Object["spec"])
	}
}

func TestReconcileSPIREGarbageCollectsStaleManagedClusterSPIFFEIDs(t *testing.T) {
	store := mustSPIREPolicyStore(t)
	desired := newClusterSPIFFEIDUnstructured()
	desired.SetName("airlock-demo-code-agent")
	desired.SetLabels(map[string]string{"airlock.dev/managed-by": "airlock-control-plane"})
	stale := newClusterSPIFFEIDUnstructured()
	stale.SetName("airlock-old-policy")
	stale.SetLabels(map[string]string{"airlock.dev/managed-by": "airlock-control-plane"})
	kube := newSPIREFakeClient(t, desired, stale)

	result, err := ReconcileSPIRE(context.Background(), store, SPIREReconcileOptions{
		Client:         kube,
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

	deleted := newClusterSPIFFEIDUnstructured()
	err = kube.Get(context.Background(), ctrlclient.ObjectKey{Name: "airlock-old-policy"}, deleted)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("stale ClusterSPIFFEID get error = %v, want not found", err)
	}
}

func TestReconcileDoesNotCollideAcrossNamespaces(t *testing.T) {
	dev := policy.CompiledPolicy{
		PolicyName: "demo",
		Workload: policy.WorkloadIdentity{
			Namespace: "dev",
			SPIFFEID:  "spiffe://airlock.local/ns/dev/sa/code-agent/component/airlock-proxy-worker",
		},
	}
	prod := dev
	prod.Workload.Namespace = "prod"
	prod.Workload.SPIFFEID = "spiffe://airlock.local/ns/prod/sa/code-agent/component/airlock-proxy-worker"

	devObject, err := clusterSPIFFEIDForWorkload(dev, SPIREReconcileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	prodObject, err := clusterSPIFFEIDForWorkload(prod, SPIREReconcileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if devObject.Metadata.Name == prodObject.Metadata.Name {
		t.Fatalf("ClusterSPIFFEID names collided: %q", devObject.Metadata.Name)
	}
	if got, want := devObject.Metadata.Name, "airlock-dev-demo"; got != want {
		t.Fatalf("dev name = %q, want %q", got, want)
	}
	if got, want := prodObject.Metadata.Name, "airlock-prod-demo"; got != want {
		t.Fatalf("prod name = %q, want %q", got, want)
	}
	if got, want := vaultPolicyName(dev), "airlock-dev-demo"; got != want {
		t.Fatalf("dev Vault policy = %q, want %q", got, want)
	}
	if got, want := vaultPolicyName(prod), "airlock-prod-demo"; got != want {
		t.Fatalf("prod Vault policy = %q, want %q", got, want)
	}
}

func mustSPIREPolicyStore(t *testing.T) *PolicyStore {
	t.Helper()
	store, err := LoadPolicyStoreWithSecretProviderConfigs(
		[]string{filepath.Join("..", "..", "fixtures", "policies", "valid-vault-provider-ref.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "workloads", "code-agent-vault.yaml")},
		[]string{filepath.Join("..", "..", "fixtures", "secret-provider-configs", "default-vault.yaml")},
	)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newSPIREFakeClient(t *testing.T, objects ...ctrlclient.Object) ctrlclient.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(spireClusterSPIFFEIDGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(spireClusterSPIFFEIDListGVK, &unstructured.UnstructuredList{})
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		Build()
}
