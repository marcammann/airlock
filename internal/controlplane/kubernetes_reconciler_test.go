package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	airlockv1 "github.com/marcammann/airlock/api/v1alpha1"
	"github.com/marcammann/airlock/internal/policy"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestReconcileKubernetesResourcesReplacesStoreAndPatchesStatus(t *testing.T) {
	kube := newAirlockFakeClient(t)
	var replaced *PolicyStore

	result, err := ReconcileKubernetesResources(context.Background(), KubernetesReconcileOptions{
		Client:    kube,
		Namespace: "airlock-system",
		ReplaceStore: func(store *PolicyStore) {
			replaced = store
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Policies != 1 || !result.SPIREReady || !result.VaultReady || result.PatchedWorkloadStatuses != 1 {
		t.Fatalf("result = %+v, want one reconciled policy and patched status", result)
	}
	if replaced == nil {
		t.Fatal("ReplaceStore was not called")
	}
	if _, ok := replaced.Get(codeAgentIdentity); !ok {
		t.Fatal("replacement store did not contain code-agent policy")
	}

	var workload policy.AirlockWorkload
	if err := kube.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "airlock-system", Name: "code-agent"}, &workload); err != nil {
		t.Fatal(err)
	}
	if workload.Status.PolicyHash == "" {
		t.Fatal("workload status policy hash is empty")
	}
	if len(workload.Status.Conditions) != 1 || workload.Status.Conditions[0].Status != "True" || workload.Status.Conditions[0].Reason != "Reconciled" {
		t.Fatalf("status conditions = %+v, want Ready=True Reconciled", workload.Status.Conditions)
	}
}

func TestReconcilerReconcilesOnCreate(t *testing.T) {
	kube := newAirlockFakeClient(t)
	var replaced *PolicyStore
	reconciler := KubernetesReconciler{Options: KubernetesReconcileOptions{
		Client:    kube,
		Namespace: "airlock-system",
		ReplaceStore: func(store *PolicyStore) {
			replaced = store
		},
	}}

	result, err := reconciler.Reconcile(context.Background(), ctrlreconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "airlock-system", Name: "code-agent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != (ctrlreconcile.Result{}) {
		t.Fatalf("result = %+v, want empty result", result)
	}
	if replaced == nil {
		t.Fatal("ReplaceStore was not called")
	}
	if _, ok := replaced.Get(codeAgentIdentity); !ok {
		t.Fatal("replacement store did not contain code-agent policy")
	}
}

func TestKubernetesReconcilerSkipsRequestsOutsideNamespace(t *testing.T) {
	reconciler := KubernetesReconciler{
		Options: KubernetesReconcileOptions{
			Namespace: "airlock-system",
			StatusPatcher: func(context.Context, ctrlclient.Client, []KubernetesPolicyStatusUpdate, bool, bool) {
				t.Fatal("StatusPatcher should not be called for another namespace")
			},
		},
	}

	result, err := reconciler.Reconcile(context.Background(), ctrlreconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "other", Name: "code-agent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != (ctrlreconcile.Result{}) {
		t.Fatalf("result = %+v, want empty result", result)
	}
}

func TestKubernetesReconcilerMapsWatchedObjectsToNamespaceRequest(t *testing.T) {
	reconciler := KubernetesReconciler{
		Options: KubernetesReconcileOptions{Namespace: "airlock-system"},
	}
	requests := reconciler.reconcileRequestForObject(context.Background(), &policy.AirlockPolicy{
		Metadata: policy.Metadata{Namespace: "airlock-system", Name: "openai"},
	})

	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
	if got, want := requests[0].Namespace, "airlock-system"; got != want {
		t.Fatalf("namespace = %q, want %q", got, want)
	}
	if got, want := requests[0].Name, "namespace"; got != want {
		t.Fatalf("name = %q, want %q", got, want)
	}
}

func TestKubernetesReconcilerIgnoresWatchedObjectsOutsideNamespace(t *testing.T) {
	reconciler := KubernetesReconciler{
		Options: KubernetesReconcileOptions{Namespace: "airlock-system"},
	}
	requests := reconciler.reconcileRequestForObject(context.Background(), &policy.SecretProviderConfig{
		Metadata: policy.Metadata{Namespace: "other", Name: "default"},
	})

	if len(requests) != 0 {
		t.Fatalf("requests = %+v, want none", requests)
	}
}

func TestReconcileKubernetesResourcesSPIREFailurePatchesReconciling(t *testing.T) {
	kube := newAirlockFakeClient(t)
	var patched bool
	var gotSPIREReady bool
	var gotVaultReady bool

	_, err := ReconcileKubernetesResources(context.Background(), KubernetesReconcileOptions{
		Client:         kube,
		Namespace:      "airlock-system",
		SPIREReconcile: true,
		ReconcileSPIRE: func(context.Context, *PolicyStore, SPIREReconcileOptions) (SPIREReconcileResult, error) {
			return SPIREReconcileResult{}, errors.New("spire unavailable")
		},
		StatusPatcher: func(_ context.Context, _ ctrlclient.Client, updates []KubernetesPolicyStatusUpdate, spireReady bool, vaultReady bool) {
			patched = true
			gotSPIREReady = spireReady
			gotVaultReady = vaultReady
			if len(updates) != 1 {
				t.Fatalf("updates = %d, want 1", len(updates))
			}
		},
	})
	if err == nil || !strings.Contains(err.Error(), "reconcile SPIRE") {
		t.Fatalf("err = %v, want SPIRE reconcile error", err)
	}
	if !patched {
		t.Fatal("StatusPatcher was not called")
	}
	if gotSPIREReady || !gotVaultReady {
		t.Fatalf("patched readiness = spire %t vault %t, want spire=false vault=true", gotSPIREReady, gotVaultReady)
	}
}

func newAirlockFakeClient(t *testing.T) ctrlclient.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := airlockv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&policy.AirlockWorkload{}).
		WithObjects(
			ptrTo(mustSecretProviderConfig(t, defaultVaultProviderConfig())),
			ptrTo(mustAirlockPolicy(t, codeAgentPolicy())),
			ptrTo(mustAirlockWorkload(t, codeAgentWorkload())),
		).
		Build()
}
