package controlplane

import (
	"context"

	controlreconcile "github.com/marcammann/airlock/internal/controlplane/reconcile"
	"github.com/marcammann/airlock/internal/policy"
)

// VaultReconcileOptions configures Vault policy/role reconciliation.
type VaultReconcileOptions = controlreconcile.VaultReconcileOptions

// VaultReconcileResult summarizes Vault reconciliation.
type VaultReconcileResult = controlreconcile.VaultReconcileResult
type vaultRole = controlreconcile.VaultRole

// ReconcileVault reconciles Vault policies and roles for current workloads.
func ReconcileVault(ctx context.Context, store *PolicyStore, opts VaultReconcileOptions) (VaultReconcileResult, error) {
	return controlreconcile.ReconcileVault(ctx, store, opts)
}

func vaultPolicyName(compiled policy.CompiledPolicy) string {
	return controlreconcile.VaultPolicyName(compiled)
}

func vaultACLPolicy(compiled policy.CompiledPolicy) (string, int, error) {
	return controlreconcile.VaultACLPolicy(compiled)
}
