package controlplane

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/marcammann/airlock/internal/policy"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// KubernetesReconcileOptions configures controller-runtime based Airlock reconciliation.
type KubernetesReconcileOptions struct {
	Client         ctrlclient.Client
	Namespace      string
	Server         *Server
	SPIREOptions   SPIREReconcileOptions
	SPIREReconcile bool
	VaultOptions   VaultReconcileOptions
	VaultReconcile bool
	StatusPatcher  func(context.Context, ctrlclient.Client, []KubernetesPolicyStatusUpdate, bool, bool)
	ReplaceStore   func(*PolicyStore)
	ReconcileSPIRE func(context.Context, *PolicyStore, SPIREReconcileOptions) (SPIREReconcileResult, error)
	ReconcileVault func(context.Context, *PolicyStore, VaultReconcileOptions) (VaultReconcileResult, error)
}

// KubernetesReconcileResult summarizes one Airlock Kubernetes reconciliation pass.
type KubernetesReconcileResult struct {
	Policies                  int
	SPIREReady                bool
	VaultReady                bool
	SPIREClusterSPIFFEIDs     int
	SPIREDeletedClusterIDs    int
	VaultPolicies             int
	VaultRoles                int
	PatchedWorkloadStatuses   int
	SkippedWorkloadNamespaces int
}

// KubernetesReconciler reconciles Airlock Kubernetes resources with controller-runtime.
type KubernetesReconciler struct {
	Options KubernetesReconcileOptions
}

// Reconcile implements controller-runtime's reconcile loop for Airlock resources.
func (r *KubernetesReconciler) Reconcile(ctx context.Context, req ctrlreconcile.Request) (ctrlreconcile.Result, error) {
	namespace := strings.TrimSpace(r.Options.Namespace)
	if namespace != "" && req.Namespace != "" && req.Namespace != namespace {
		return ctrlreconcile.Result{}, nil
	}
	_, err := ReconcileKubernetesResources(ctx, r.Options)
	return ctrlreconcile.Result{}, err
}

// SetupWithManager registers the Airlock reconciler with a controller-runtime manager.
func (r *KubernetesReconciler) SetupWithManager(mgr manager.Manager) error {
	if r.Options.Client == nil {
		r.Options.Client = mgr.GetClient()
	}
	return builder.ControllerManagedBy(mgr).
		Named("airlock-workload").
		For(&policy.AirlockWorkload{}).
		Watches(&policy.AirlockPolicy{}, handler.EnqueueRequestsFromMapFunc(r.reconcileRequestForObject)).
		Watches(&policy.SecretProviderConfig{}, handler.EnqueueRequestsFromMapFunc(r.reconcileRequestForObject)).
		Complete(r)
}

func (r *KubernetesReconciler) reconcileRequestForObject(_ context.Context, object ctrlclient.Object) []ctrlreconcile.Request {
	namespace := strings.TrimSpace(object.GetNamespace())
	if namespace == "" {
		namespace = strings.TrimSpace(r.Options.Namespace)
	}
	if namespace == "" {
		return nil
	}
	configuredNamespace := strings.TrimSpace(r.Options.Namespace)
	if configuredNamespace != "" && namespace != configuredNamespace {
		return nil
	}
	return []ctrlreconcile.Request{{
		NamespacedName: types.NamespacedName{
			Namespace: namespace,
			Name:      "namespace",
		},
	}}
}

// ReconcileKubernetesResources executes one Airlock Kubernetes reconciliation pass.
func ReconcileKubernetesResources(ctx context.Context, opts KubernetesReconcileOptions) (KubernetesReconcileResult, error) {
	if opts.Client == nil {
		return KubernetesReconcileResult{}, fmt.Errorf("kubernetes client is required")
	}
	namespace := strings.TrimSpace(opts.Namespace)
	if namespace == "" {
		return KubernetesReconcileResult{}, fmt.Errorf("kubernetes policy namespace is required")
	}

	store, updates, err := LoadPolicyStoreFromKubernetesClient(ctx, opts.Client, namespace)
	if err != nil {
		return KubernetesReconcileResult{}, err
	}
	result := KubernetesReconcileResult{Policies: store.Len()}

	spireReady := !opts.SPIREReconcile
	if opts.SPIREReconcile {
		reconcileSPIRE := opts.ReconcileSPIRE
		if reconcileSPIRE == nil {
			reconcileSPIRE = ReconcileSPIRE
		}
		spireOpts := opts.SPIREOptions
		if spireOpts.Client == nil {
			spireOpts.Client = opts.Client
		}
		spireResult, err := reconcileSPIRE(ctx, store, spireOpts)
		if err != nil {
			patcher := kubernetesStatusPatcher(opts)
			patcher(ctx, opts.Client, updates, false, !opts.VaultReconcile)
			result.PatchedWorkloadStatuses = len(updates)
			return result, fmt.Errorf("reconcile SPIRE: %w", err)
		}
		spireReady = true
		result.SPIREClusterSPIFFEIDs = spireResult.ClusterSPIFFEIDs
		result.SPIREDeletedClusterIDs = spireResult.DeletedClusterSPIFFEIDs
	}

	vaultReady := !opts.VaultReconcile
	if opts.VaultReconcile {
		reconcileVault := opts.ReconcileVault
		if reconcileVault == nil {
			reconcileVault = ReconcileVault
		}
		vaultOpts := opts.VaultOptions
		if vaultOpts.Audit == nil {
			vaultOpts.Audit = io.Discard
		}
		vaultResult, err := reconcileVault(ctx, store, vaultOpts)
		if err != nil {
			patcher := kubernetesStatusPatcher(opts)
			patcher(ctx, opts.Client, updates, spireReady, false)
			result.PatchedWorkloadStatuses = len(updates)
			return result, fmt.Errorf("reconcile Vault: %w", err)
		}
		vaultReady = true
		result.VaultPolicies = vaultResult.Policies
		result.VaultRoles = vaultResult.Roles
	}

	if opts.ReplaceStore != nil {
		opts.ReplaceStore(store)
	} else if opts.Server != nil {
		opts.Server.ReplaceStore(store)
	}

	patcher := kubernetesStatusPatcher(opts)
	patcher(ctx, opts.Client, updates, spireReady, vaultReady)
	result.SPIREReady = spireReady
	result.VaultReady = vaultReady
	result.PatchedWorkloadStatuses = len(updates)
	return result, nil
}

func kubernetesStatusPatcher(opts KubernetesReconcileOptions) func(context.Context, ctrlclient.Client, []KubernetesPolicyStatusUpdate, bool, bool) {
	if opts.StatusPatcher != nil {
		return opts.StatusPatcher
	}
	return PatchKubernetesStatusesWithClient
}

// PatchKubernetesStatusesWithClient patches workload statuses after a reconcile pass.
func PatchKubernetesStatusesWithClient(ctx context.Context, kubeClient ctrlclient.Client, updates []KubernetesPolicyStatusUpdate, spireReady bool, vaultReady bool) {
	for _, update := range updates {
		status := update.Status
		status.Spire.Ready = spireReady
		status.Vault.Ready = vaultReady
		if len(status.Conditions) == 0 {
			status.Conditions = []policy.StatusCondition{{Type: "Ready"}}
		}
		if spireReady && vaultReady {
			status.Conditions[0].Status = "True"
			status.Conditions[0].Reason = "Reconciled"
			status.Conditions[0].Message = ""
		} else {
			status.Conditions[0].Status = "False"
			status.Conditions[0].Reason = "Reconciling"
		}
		if err := PatchAirlockWorkloadStatusWithClient(ctx, kubeClient, update.Workload, status); err != nil {
			slog.Error("patch AirlockWorkload status failed", "namespace", update.Workload.Metadata.Namespace, "name", update.Workload.Metadata.Name, "error", err)
		}
	}
}
