# OpenCode Headless Server With Local TUI

This example runs the OpenCode backend server in Docker Compose, wraps its
proxy-aware outbound HTTP(S) traffic with Airlock, and attaches to it from the
local OpenCode TUI. The Airlock policy allows only the OpenAI API endpoint at
`api.openai.com:443`.

Topology:

```text
Docker Compose
  airlock-proxy
    airlock-proxy-worker builtin HTTP proxy
    local OpenAI-only allowlist policy

  opencode-server
    local image with opencode-ai installed from npm
    default model -> openai/gpt-5.5
    /workspace -> this repository
    ~/.local/share/opencode -> persisted Compose volume
    ~/.config/opencode -> persisted Compose volume

Host terminal
  opencode attach http://localhost:4096 --dir /workspace
```

Start the server:

```sh
make opencode-headless-up
```

Attach from your host terminal:

```sh
OPENCODE_SERVER_PASSWORD=opencode-local \
  opencode attach http://localhost:4096 --dir /workspace
```

The default basic-auth username is `opencode`. Override the local password or
port if needed:

```sh
OPENCODE_SERVER_PASSWORD=change-me OPENCODE_PORT=4097 make opencode-headless-up

OPENCODE_SERVER_PASSWORD=change-me \
  opencode attach http://localhost:4097 --dir /workspace
```

Provider credentials can be supplied either through your host environment before
starting Compose:

```sh
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
make opencode-headless-up
```

The OpenCode config is mounted from `config/opencode.json` and currently sets:

```json
{
  "model": "openai/gpt-5.5"
}
```

Or by using OpenCode auth inside the container and keeping the persisted
`opencode-data` volume:

```sh
docker compose -f examples/compose/opencode-headless/compose.yaml run --rm opencode-server auth login
```

Useful commands:

```sh
make opencode-headless-logs
make opencode-headless-down
make opencode-headless-clean
```

`opencode-headless-clean` removes the Compose volumes, including persisted
OpenCode sessions/config/auth data for this example.

Notes:

- OpenCode receives `HTTP_PROXY` and `HTTPS_PROXY` pointing at Airlock, with
  `NO_PROXY` set for localhost so local attach traffic does not loop through the
  proxy.
- The Airlock policy at `policy/openai-api.yaml` allows `api.openai.com:443`.
  Any other proxy-aware external model/API request should fail closed.
- This is not yet a hard Docker network egress sandbox: a process that ignores
  proxy environment variables could still use the container network directly.
  The next Airlock pass should add network-level enforcement if we want this
  Compose shape to be fail-closed for all traffic.
- The official OpenCode Docker image is `ghcr.io/anomalyco/opencode`; this
  example builds a small local image from `node:24-bookworm-slim` and installs
  `opencode-ai` through npm so the example can add Git/Ripgrep tooling and avoid
  depending on the published image internals.
- Keep your local `opencode` CLI reasonably close to the server version. If
  `opencode attach` behaves oddly, run `opencode upgrade` locally or rebuild the
  Compose image.
- The server port is bound to `127.0.0.1` only.
- The server is protected with `OPENCODE_SERVER_PASSWORD` because the OpenCode
  server exposes project and agent APIs.
- `NO_PROXY` is set for localhost so OpenCode's local client/server traffic
  does not get routed through an HTTP proxy later.
