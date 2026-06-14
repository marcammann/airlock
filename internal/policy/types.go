package policy

import airlockv1 "github.com/marcammann/airlock/api/v1alpha1"

const APIVersion = airlockv1.APIVersion

type AirlockPolicy = airlockv1.AirlockPolicy
type AirlockWorkload = airlockv1.AirlockWorkload
type Metadata = airlockv1.Metadata
type PolicySpec = airlockv1.PolicySpec
type WorkloadSpec = airlockv1.WorkloadSpec
type SecretProviderRef = airlockv1.SecretProviderRef
type PolicyRef = airlockv1.PolicyRef
type WorkloadIdentity = airlockv1.WorkloadIdentity
type EgressRule = airlockv1.EgressRule
type RewriteRule = airlockv1.RewriteRule
type SecretRef = airlockv1.SecretRef
type CompiledPolicy = airlockv1.CompiledPolicy
type CompiledSecretProvider = airlockv1.CompiledSecretProvider
type CompiledVaultProvider = airlockv1.CompiledVaultProvider
type SecretProviderConfig = airlockv1.SecretProviderConfig
type SecretProviderConfigSpec = airlockv1.SecretProviderConfigSpec
type VaultProviderSpec = airlockv1.VaultProviderSpec
type VaultAuthSpec = airlockv1.VaultAuthSpec
type VaultProviderDefaults = airlockv1.VaultProviderDefaults
type Status = airlockv1.Status
type SubsystemStatus = airlockv1.SubsystemStatus
type StatusCondition = airlockv1.StatusCondition
