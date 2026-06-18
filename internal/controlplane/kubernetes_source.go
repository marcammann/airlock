package controlplane

import (
	"context"

	controlstore "github.com/marcammann/airlock/internal/controlplane/store"
	"github.com/marcammann/airlock/internal/policy"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// KubernetesPolicyStatusUpdate is a workload status update produced during K8s load.
type KubernetesPolicyStatusUpdate = controlstore.KubernetesPolicyStatusUpdate

// LoadPolicyStoreFromKubernetesClient loads Airlock resources from Kubernetes.
func LoadPolicyStoreFromKubernetesClient(ctx context.Context, kube ctrlclient.Client, namespace string) (*PolicyStore, []KubernetesPolicyStatusUpdate, error) {
	return controlstore.LoadPolicyStoreFromKubernetesClient(ctx, kube, namespace)
}

// PatchAirlockWorkloadStatusWithClient patches one workload status.
func PatchAirlockWorkloadStatusWithClient(ctx context.Context, kube ctrlclient.Client, input policy.AirlockWorkload, status policy.Status) error {
	return controlstore.PatchAirlockWorkloadStatusWithClient(ctx, kube, input, status)
}
