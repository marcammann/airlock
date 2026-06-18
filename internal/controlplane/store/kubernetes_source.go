package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/marcammann/airlock/internal/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// KubernetesPolicyStatusUpdate is a status patch to apply after compiling a workload from Kubernetes.
type KubernetesPolicyStatusUpdate struct {
	Workload policy.AirlockWorkload
	Status   policy.Status
}

// LoadPolicyStoreFromKubernetesClient loads Airlock resources with a controller-runtime client.
func LoadPolicyStoreFromKubernetesClient(ctx context.Context, kube ctrlclient.Client, namespace string) (*PolicyStore, []KubernetesPolicyStatusUpdate, error) {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, nil, fmt.Errorf("kubernetes policy namespace is required")
	}
	if kube == nil {
		return nil, nil, fmt.Errorf("kubernetes client is required")
	}

	var providerConfigList policy.SecretProviderConfigList
	if err := kube.List(ctx, &providerConfigList, ctrlclient.InNamespace(namespace)); err != nil {
		return nil, nil, fmt.Errorf("list SecretProviderConfig objects: %w", err)
	}
	providerConfigs := map[string]policy.SecretProviderConfig{}
	for _, item := range providerConfigList.Items {
		defaultTypeMeta(&item.TypeMeta, "SecretProviderConfig")
		if item.Metadata.Namespace == "" {
			item.Metadata.Namespace = namespace
		}
		if err := policy.ValidateSecretProviderConfig(item); err != nil {
			return nil, nil, fmt.Errorf("validate SecretProviderConfig %s/%s: %w", item.Metadata.Namespace, item.Metadata.Name, err)
		}
		key := ProviderConfigKey(item.Metadata.Namespace, item.Metadata.Name)
		if existing, ok := providerConfigs[key]; ok {
			return nil, nil, fmt.Errorf("secret provider config %q duplicates %q", item.Metadata.Name, existing.Metadata.Name)
		}
		providerConfigs[key] = item
	}

	var policyList policy.AirlockPolicyList
	if err := kube.List(ctx, &policyList, ctrlclient.InNamespace(namespace)); err != nil {
		return nil, nil, fmt.Errorf("list AirlockPolicy objects: %w", err)
	}
	policies := make([]policy.AirlockPolicy, 0, len(policyList.Items))
	for _, item := range policyList.Items {
		defaultTypeMeta(&item.TypeMeta, "AirlockPolicy")
		if item.Metadata.Namespace == "" {
			item.Metadata.Namespace = namespace
		}
		item = policy.NormalizePolicy(item)
		if err := policy.Validate(item); err != nil {
			slog.Warn("dropping invalid AirlockPolicy", "namespace", item.Metadata.Namespace, "name", item.Metadata.Name, "error", err)
			continue
		}
		policies = append(policies, item)
	}

	var workloadList policy.AirlockWorkloadList
	if err := kube.List(ctx, &workloadList, ctrlclient.InNamespace(namespace)); err != nil {
		return nil, nil, fmt.Errorf("list AirlockWorkload objects: %w", err)
	}
	for i := range workloadList.Items {
		defaultTypeMeta(&workloadList.Items[i].TypeMeta, "AirlockWorkload")
		if workloadList.Items[i].Metadata.Namespace == "" {
			workloadList.Items[i].Metadata.Namespace = namespace
		}
	}

	return policyStoreFromKubernetesResources(policies, workloadList.Items, providerConfigs)
}

func defaultTypeMeta(meta *metav1.TypeMeta, kind string) {
	if meta.APIVersion == "" {
		meta.APIVersion = policy.APIVersion
	}
	if meta.Kind == "" {
		meta.Kind = kind
	}
}

func policyStoreFromKubernetesResources(policies []policy.AirlockPolicy, workloads []policy.AirlockWorkload, providerConfigs map[string]policy.SecretProviderConfig) (*PolicyStore, []KubernetesPolicyStatusUpdate, error) {
	for i := range policies {
		policies[i] = policy.NormalizePolicy(policies[i])
	}
	compiledPolicies := make([]policy.CompiledPolicy, 0, len(workloads))
	updates := make([]KubernetesPolicyStatusUpdate, 0, len(workloads))
	for _, input := range workloads {
		providerConfig, err := ResolveSecretProviderConfig(input, providerConfigs)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve secret provider for workload %s/%s: %w", input.Metadata.Namespace, input.Metadata.Name, err)
		}
		compiled, err := policy.CompileWorkloadWithSecretProvider(input, policies, providerConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("compile workload %s/%s: %w", input.Metadata.Namespace, input.Metadata.Name, err)
		}
		compiledPolicies = append(compiledPolicies, compiled)
		updates = append(updates, KubernetesPolicyStatusUpdate{
			Workload: input,
			Status:   ReadyWorkloadStatus(input, compiled, false),
		})
	}

	store, err := NewPolicyStoreFromResources(policies, workloads, compiledPolicies)
	if err != nil {
		return nil, nil, err
	}
	return store, updates, nil
}

// PatchAirlockWorkloadStatusWithClient patches workload status with a controller-runtime client.
func PatchAirlockWorkloadStatusWithClient(ctx context.Context, kube ctrlclient.Client, input policy.AirlockWorkload, status policy.Status) error {
	if kube == nil {
		return fmt.Errorf("kubernetes client is required")
	}
	namespace := strings.TrimSpace(input.Metadata.Namespace)
	name := strings.TrimSpace(input.Metadata.Name)
	if namespace == "" || name == "" {
		return fmt.Errorf("workload namespace and name are required for status patch")
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &policy.AirlockWorkload{}
		if err := kube.Get(ctx, ctrlclient.ObjectKey{Namespace: namespace, Name: name}, current); err != nil {
			return fmt.Errorf("get AirlockWorkload %s/%s: %w", namespace, name, err)
		}
		base := current.DeepCopyObject().(*policy.AirlockWorkload)
		current.Status = status
		if err := kube.Status().Patch(ctx, current, ctrlclient.MergeFrom(base)); err != nil {
			return fmt.Errorf("patch AirlockWorkload %s/%s status: %w", namespace, name, err)
		}
		return nil
	})
}

// ReadyWorkloadStatus builds the status reported after a workload compiles and optional Vault reconciliation completes.
func ReadyWorkloadStatus(input policy.AirlockWorkload, compiled policy.CompiledPolicy, vaultReady bool) policy.Status {
	status := "False"
	if vaultReady {
		status = "True"
	}
	return policy.Status{
		ObservedGeneration: input.Metadata.Generation,
		PolicyHash:         CompiledPolicyHash(compiled),
		Spire:              policy.SubsystemStatus{Ready: true},
		Vault:              policy.SubsystemStatus{Ready: vaultReady},
		Conditions: []policy.StatusCondition{{
			Type:   "Ready",
			Status: status,
			Reason: func() string {
				if vaultReady {
					return "Reconciled"
				}
				return "Compiled"
			}(),
		}},
	}
}

// FailedWorkloadStatus builds the status reported when workload reconciliation fails.
func FailedWorkloadStatus(input policy.AirlockWorkload, reason string, message string) policy.Status {
	return policy.Status{
		ObservedGeneration: input.Metadata.Generation,
		Spire:              policy.SubsystemStatus{Ready: true},
		Vault:              policy.SubsystemStatus{Ready: false},
		Conditions: []policy.StatusCondition{{
			Type:    "Ready",
			Status:  "False",
			Reason:  reason,
			Message: message,
		}},
	}
}

// CompiledPolicyHash returns a stable hash for a compiled policy status.
func CompiledPolicyHash(compiled policy.CompiledPolicy) string {
	data, _ := json.Marshal(compiled)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
