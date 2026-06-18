package policy

import airlockv1 "github.com/marcammann/airlock/api/v1alpha1"

// APIVersion is the supported Airlock resource API version.
const APIVersion = airlockv1.APIVersion

// AirlockPolicy is the source policy resource.
type AirlockPolicy = airlockv1.AirlockPolicy

// AirlockPolicyList is a list of source policy resources.
type AirlockPolicyList = airlockv1.AirlockPolicyList

// AirlockWorkload assigns policies to a workload identity.
type AirlockWorkload = airlockv1.AirlockWorkload

// AirlockWorkloadList is a list of workload resources.
type AirlockWorkloadList = airlockv1.AirlockWorkloadList

// Metadata contains Airlock resource identity.
type Metadata = airlockv1.Metadata

// PolicySpec contains AirlockPolicy settings.
type PolicySpec = airlockv1.PolicySpec

// WorkloadSpec contains AirlockWorkload settings.
type WorkloadSpec = airlockv1.WorkloadSpec

// SecretProviderRef references a SecretProviderConfig.
type SecretProviderRef = airlockv1.SecretProviderRef

// PolicyRef references an AirlockPolicy from a workload.
type PolicyRef = airlockv1.PolicyRef

// WorkloadIdentity identifies a protected workload.
type WorkloadIdentity = airlockv1.WorkloadIdentity

// EgressRule allows one egress destination.
type EgressRule = airlockv1.EgressRule

// RewriteRule injects or changes request data for an egress rule.
type RewriteRule = airlockv1.RewriteRule

// SecretRef identifies a secret consumed by a rewrite.
type SecretRef = airlockv1.SecretRef

// CompiledPolicy is the worker-consumable policy document.
type CompiledPolicy = airlockv1.CompiledPolicy

// CompiledSecretProvider contains worker-consumable secret provider config.
type CompiledSecretProvider = airlockv1.CompiledSecretProvider

// CompiledVaultProvider contains worker-consumable Vault settings.
type CompiledVaultProvider = airlockv1.CompiledVaultProvider

// SecretProviderConfig is a source secret provider resource.
type SecretProviderConfig = airlockv1.SecretProviderConfig

// SecretProviderConfigList is a list of secret provider configs.
type SecretProviderConfigList = airlockv1.SecretProviderConfigList

// SecretProviderConfigSpec contains secret provider settings.
type SecretProviderConfigSpec = airlockv1.SecretProviderConfigSpec

// VaultProviderSpec contains Vault provider settings.
type VaultProviderSpec = airlockv1.VaultProviderSpec

// VaultAuthSpec configures Vault authentication.
type VaultAuthSpec = airlockv1.VaultAuthSpec

// VaultProviderDefaults supplies default Vault secret fields.
type VaultProviderDefaults = airlockv1.VaultProviderDefaults

// Status is the shared Airlock resource status.
type Status = airlockv1.Status

// SubsystemStatus describes one reconciled subsystem.
type SubsystemStatus = airlockv1.SubsystemStatus

// StatusCondition describes one resource status condition.
type StatusCondition = airlockv1.StatusCondition
