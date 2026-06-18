package controlplane

import (
	"context"

	controlreconcile "github.com/marcammann/airlock/internal/controlplane/reconcile"
	"github.com/marcammann/airlock/internal/policy"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var (
	spireClusterSPIFFEIDGVK     = controlreconcile.SPIREClusterSPIFFEIDGVK
	spireClusterSPIFFEIDListGVK = controlreconcile.SPIREClusterSPIFFEIDListGVK
)

// SPIREReconcileOptions configures SPIRE ClusterSPIFFEID reconciliation.
type SPIREReconcileOptions = controlreconcile.SPIREReconcileOptions

// SPIREReconcileResult summarizes SPIRE reconciliation.
type SPIREReconcileResult = controlreconcile.SPIREReconcileResult
type clusterSPIFFEID = controlreconcile.ClusterSPIFFEID

// ReconcileSPIRE reconciles SPIRE resources for current workloads.
func ReconcileSPIRE(ctx context.Context, store *PolicyStore, opts SPIREReconcileOptions) (SPIREReconcileResult, error) {
	return controlreconcile.ReconcileSPIRE(ctx, store, opts)
}

func clusterSPIFFEIDForWorkload(compiled policy.CompiledPolicy, opts SPIREReconcileOptions) (clusterSPIFFEID, error) {
	return controlreconcile.ClusterSPIFFEIDForWorkload(compiled, opts)
}

func newClusterSPIFFEIDUnstructured() *unstructured.Unstructured {
	return controlreconcile.NewClusterSPIFFEIDUnstructured()
}
