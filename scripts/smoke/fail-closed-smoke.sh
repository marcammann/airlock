#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

cd "$ROOT_DIR"
go test ./internal/controlplane -run 'TestInjectionWebhook(InjectsEnvoyAndProxyWorker|ExistingEnvoyModeInjectsOnlyProxyWorker)$'

go test ./cmd/airlock-proxy-worker -run 'TestRunControlPlaneOutageFailsBeforeStartup$'
go test ./internal/proxyworker -run 'Test(VaultSecretProviderResolveFailsWhenCacheEntryExpired|VaultSecretCacheTTLTracksVaultTokenLease|VaultSecretCacheTTLRejectsUnknownTokenLease|VaultReadKV2Non200FailsClosed|SPIFFEPolicyFetchFailsBeforeControlPlaneRequestWhenWorkloadAPIMissing|SPIFFEVaultAuthFailsBeforeVaultRequestWhenWorkloadAPIMissing|BuiltinProxySecretFailureDoesNotReachUpstream|ExtProcSecretFailureDoesNotReturnMutation|ExtProcGRPCServerSecretFailureReturnsImmediateError|ExtProcPolicyRevocationDeniesPreviouslyAllowedDestination|SDSServerRefreshesLeafAfterCacheWindow)$'

echo "fail-closed smoke passed"
