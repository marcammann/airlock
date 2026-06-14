# Secret Provider Contributions

Airlock policies reference secrets through `SecretRef` values. The proxy worker
turns those references into concrete values through the `SecretProvider`
interface:

```go
type SecretProvider interface {
    Resolve(SecretRef) (string, error)
}
```

Providers must fail closed. If a secret is missing, expired, malformed, or the
backend cannot be reached, return an error. Do not return an empty string as a
fallback.

## Current Layout

The proxy worker keeps provider code in `proxy-worker/internal/worker`:

- `secret_provider.go`: common `SecretProvider` interface.
- `secret_provider_env_file.go`: local env/file provider.
- `secret_provider_factory.go`: policy inspection and provider selection.
- `secret_provider_vault.go`: Vault provider, auth, preloading, and cache.
- `vault_client.go`: Vault HTTP API helpers.

This keeps provider internals separate while avoiding a larger package split
until the policy model has more than one remote provider.

## Adding A Provider

1. Extend the API types in `types.go`.
   - Add provider-specific fields to `SecretRef` if the secret reference itself
     needs new coordinates.
   - Add a compiled provider config under `CompiledSecretProvider` if the
     backend needs shared configuration such as address, auth mount, audience,
     role, tenant, or region.

2. Extend validation.
   - Update `validateSecretRef` in `types.go`.
   - Keep provider requirements explicit. A bad policy should fail at load time,
     not during request processing.

3. Add a provider file.
   - Prefer `secret_provider_<name>.go`.
   - Keep backend HTTP/API client helpers in a separate file if they grow.
   - Redact secret values before logging. Secret coordinates such as mount,
     path, and key are acceptable only when they are not themselves sensitive.

4. Wire provider selection.
   - Update `NewSecretProviderForPolicy` in `secret_provider_factory.go`.
   - Add a helper like `PolicyHas<Name>SecretRefs` if the provider should only
     initialize when referenced.

5. Add fixtures and tests.
   - Add policy fixtures under `fixtures/policies`.
   - Add provider config fixtures under `fixtures/secret-provider-configs` when
     applicable.
   - Unit test validation, provider selection, and redaction behavior.
   - Add a smoke script only when the backend needs end-to-end coverage.

## Runtime Contract

- Providers should preload or validate referenced secrets before serving traffic
  whenever the backend supports it.
- Request-time `Resolve` should be quick and deterministic.
- Caches must have explicit expiration behavior.
- Expired cached secrets should fail closed until refresh support exists.
- Provider logs must prove what happened without exposing values.

## Examples

Local examples:

- `env`: `valueFrom.provider=env`, `valueFrom.env=ENV_VAR_NAME`
- `file`: `valueFrom.provider=file`, `valueFrom.file=/mounted/secret`

Remote example:

- `vault`: configured through the compiled secret provider config, with
  per-reference `mount`, `engine`, `path`, and `key` coordinates.

Vault `SecretProviderConfig` can provide defaults for `mount`, `engine`, and
`pathPrefix`. The prefix is applied by the control plane during compilation, so
policies can use logical paths while each namespace/environment maps them to its
own Vault layout.
