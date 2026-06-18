# Proxy Worker Conventions

## Receivers

Use pointer receivers for providers, servers, reporters, and other types that
hold state, cache values, own goroutines, or may gain those responsibilities.
`EnvFileSecretProvider` and `VaultSecretProvider` both use pointer receivers so
their cache and refresh behavior stay consistent.

Use value receivers only for small immutable value types where copying is
obviously safe and intentional.
