# Codex App Server With Local Client

This example runs the experimental Codex app server in Docker Compose, wraps
proxy-aware outbound HTTP(S) traffic with Airlock, and exposes the app-server
WebSocket on localhost.

Topology:

```text
Docker Compose
  airlock-proxy
    airlock-proxy-worker builtin HTTP proxy
    local Codex/OpenAI allowlist policy

  codex-app-server
    local image with @openai/codex installed from npm
    app-server listening on ws://0.0.0.0:4100
    /workspace -> this repository
    /codex-home -> examples/compose/codex-app-server/home

Host terminal
  codex --remote ws://127.0.0.1:4100
```

Start the server:

```sh
make codex-app-server-up
```

Connect from your host terminal:

```sh
make codex-app-server-connect
```

The WebSocket listener is published on `127.0.0.1` only. It uses a demo
capability token from `secrets/ws-token`; replace that token before using this
outside local development.

Useful commands:

```sh
make codex-app-server-logs
make codex-app-server-down
make codex-app-server-clean
```

Notes:

- The app-server transport is experimental.
- `home/config.toml` sets the default model to `gpt-5.5` and trusts
  `/workspace`.
- The app-server is started with `--remote-control` so the desktop app's remote
  device flow can use the same container.
- OpenAI account/auth state can live under `home/`; the directory ignores
  everything except the demo config by default.
- Codex receives `HTTP_PROXY` and `HTTPS_PROXY` pointing at Airlock, with
  `NO_PROXY` set for localhost.
- The Airlock policy at `policy/openai-api.yaml` allows `api.openai.com:443`,
  `chatgpt.com:443`, and `files.openai.com:443`. Codex startup currently also
  attempts GitHub update or metadata checks, which remain denied by default.
