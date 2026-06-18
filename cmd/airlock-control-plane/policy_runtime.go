package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/marcammann/airlock/internal/controlplane"
)

type controlPlanePolicyRuntime struct {
	Store        *controlplane.PolicyStore
	KubeRuntime  *kubernetesControllerRuntime
	SPIREOptions controlplane.SPIREReconcileOptions
	VaultToken   string
}

func buildControlPlanePolicyRuntime(ctx context.Context, config controlPlaneConfig) (*controlPlanePolicyRuntime, error) {
	if !config.KubeSource && len(config.PolicyPaths) == 0 {
		return nil, fmt.Errorf("at least one --policy or AIRLOCK_POLICY_PATHS entry is required")
	}
	if !config.KubeSource && len(config.WorkloadPaths) == 0 {
		return nil, fmt.Errorf("at least one --workload or AIRLOCK_WORKLOAD_PATHS entry is required")
	}

	runtime := &controlPlanePolicyRuntime{
		SPIREOptions: controlplane.SPIREReconcileOptions{
			ClassName:      config.SPIREClassName,
			PodLabel:       config.SPIREPodLabel,
			PodValue:       config.SPIREPodValue,
			GarbageCollect: config.SPIREGarbageCollect,
			Audit:          os.Stderr,
		},
	}

	var kubeStatusUpdates []controlplane.KubernetesPolicyStatusUpdate
	var err error
	if config.KubeSource {
		runtime.KubeRuntime, err = newKubernetesControllerRuntime(config.KubeNamespace, config.KubeLeaderElection, config.KubeReconcileInterval, kubernetesWebhookConfig{
			Listen:       config.WebhookListen,
			CertFile:     config.WebhookCertFile,
			KeyFile:      config.WebhookKeyFile,
			ClientCAFile: config.WebhookClientCAFile,
		})
		if err != nil {
			return nil, err
		}
		runtime.SPIREOptions.Client = runtime.KubeRuntime.DirectClient
		runtime.Store, kubeStatusUpdates, err = controlplane.LoadPolicyStoreFromKubernetesClient(ctx, runtime.KubeRuntime.DirectClient, config.KubeNamespace)
	} else {
		runtime.Store, err = controlplane.LoadPolicyStoreWithSecretProviderConfigs(config.PolicyPaths, config.WorkloadPaths, config.SecretProviderConfigPaths)
	}
	if err != nil {
		return nil, err
	}
	if config.SPIREReconcile && runtime.SPIREOptions.Client == nil {
		runtime.SPIREOptions.Client, err = newKubernetesDirectClient()
		if err != nil {
			return nil, err
		}
	}

	spireReady := !config.SPIREReconcile
	if config.SPIREReconcile {
		result, err := controlplane.ReconcileSPIRE(ctx, runtime.Store, runtime.SPIREOptions)
		if err != nil {
			return nil, err
		}
		spireReady = true
		slog.Info("airlock-control-plane reconciled SPIRE intent", "clusterSPIFFEIDs", result.ClusterSPIFFEIDs, "deletedClusterSPIFFEIDs", result.DeletedClusterSPIFFEIDs)
	}

	vaultReady := !config.VaultReconcile
	if config.VaultReconcile {
		runtime.VaultToken, err = resolveSecretValue(config.VaultAdminToken, config.VaultAdminTokenFile)
		if err != nil {
			return nil, err
		}
		result, err := controlplane.ReconcileVault(ctx, runtime.Store, controlplane.VaultReconcileOptions{
			AdminToken: runtime.VaultToken,
			Audit:      os.Stderr,
		})
		if err != nil {
			return nil, err
		}
		vaultReady = true
		slog.Info("airlock-control-plane reconciled Vault intent", "policies", result.Policies, "roles", result.Roles)
	}
	if config.KubeSource {
		controlplane.PatchKubernetesStatusesWithClient(ctx, runtime.KubeRuntime.DirectClient, kubeStatusUpdates, spireReady, vaultReady)
	}
	return runtime, nil
}
