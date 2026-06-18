#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

cd "$ROOT_DIR"
go test ./internal/controlplane -run 'TestInjectionWebhook(InjectsEnvoyAndProxyWorker|ExistingEnvoyModeInjectsOnlyProxyWorker)$'

go test ./cmd/airlock-proxy-worker -run 'TestRunControlPlaneOutageFailsBeforeStartup$'
go test ./internal/proxyworker/secrets -run 'Test(VaultSecretProviderResolveFailsWhenCacheEntryExpired|VaultSecretCacheTTLTracksVaultTokenLease|VaultSecretCacheTTLRejectsUnknownTokenLease|VaultReadKV2Non200FailsClosed|SPIFFEVaultAuthFailsBeforeVaultRequestWhenWorkloadAPIMissing)$'
go test ./internal/proxyworker/extproc -run 'TestExtProcGRPCServerSecretFailureReturnsImmediateError$'
go test ./internal/proxyworker/builtin -run 'TestSDSServerRefreshesLeafAfterCacheWindow$'
go test ./internal/proxyworker -run 'Test(SPIFFEPolicyFetchFailsBeforeControlPlaneRequestWhenWorkloadAPIMissing|BuiltinProxySecretFailureDoesNotReachUpstream|ExtProcSecretFailureDoesNotReturnMutation|ExtProcPolicyRevocationDeniesPreviouslyAllowedDestination)$'

echo "fail-closed smoke passed"
