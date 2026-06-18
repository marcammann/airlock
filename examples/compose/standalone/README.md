# Standalone Builtin HTTP Proxy

This example runs Airlock without a control plane. A single builtin HTTP proxy
loads a local compiled policy and the app profile chooses either OpenCode or
Codex.

OpenCode:

```sh
docker compose -f examples/compose/standalone/compose.yaml --profile opencode up -d --build
opencode attach http://localhost:4096 --dir /workspace --username opencode --password opencode-local
```

Codex app-server:

```sh
docker compose -f examples/compose/standalone/compose.yaml --profile codex up -d --build
CODEX_REMOTE_AUTH_TOKEN="$(cat examples/compose/standalone/secrets/ws-token)" \
  codex --remote ws://127.0.0.1:${CODEX_APP_SERVER_PORT:-4100} \
  --remote-auth-token-env CODEX_REMOTE_AUTH_TOKEN
```

Cleanup:

```sh
docker compose -f examples/compose/standalone/compose.yaml down -v
```
