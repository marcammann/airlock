# Daytona Soft Sandbox

This example builds a single Daytona-compatible sandbox image that embeds
Airlock without a control plane.

The image follows Daytona's default sandbox Dockerfile shape, but starts from
the lighter parent image directly:

```text
mcr.microsoft.com/devcontainers/python:3.14
```

It keeps the Daytona user, Python runtime, common shell/network tools, and a
Daytona-friendly idle image entrypoint, while deliberately leaving out the
heavy desktop stack: Chromium, X11, VNC, XFCE, ffmpeg, accessibility libraries,
and the large preinstalled ML/agent package set. Airlock is layered in as an
additional binary and proxy start script.

It is intentionally a **soft** boundary:

- Daytona process/code execution and the agent process run as the `daytona`
  Unix user.
- Airlock runs as the `airlock` Unix user.
- The `daytona` user can only start the Airlock proxy as `airlock` through
  sudo; it does not get a root bridge.
- The policy is local at `/opt/airlock/policies/openai-api.yaml`.
- Secrets are written into `/run/daytona-secrets/secrets.env`, a precreated
  write-only file for `daytona`, then expanded into Airlock-only files under
  `/run/airlock/secrets`, owned by `airlock:airlock`, mode `0400`.
- The `daytona` user can write the source secret but cannot read it back, and
  cannot read the Airlock secret file or MITM CA private key.
- The workspace receives proxy and CA environment variables, but not the API
  key.

Use this when you want the "copy the Airlock binary into the agent image" DX.
It is not equivalent to a sidecar or customer-managed compute deployment with a
separate network namespace.

## Airlock Artifact Image

The Daytona image does not build Go itself. It copies the Airlock proxy worker
from the scratch artifact image that builds all Airlock Go binaries:

```text
ghcr.io/marcammann/airlock:dev
```

The artifact image currently contains:

```text
/airlock-control-plane
/airlock-proxy-worker
```

Build the local artifact image:

```sh
docker buildx build --load \
  -f build/package/Dockerfile.artifacts \
  -t ghcr.io/marcammann/airlock:dev \
  .
```

Then build the Daytona image from that artifact:

```sh
docker buildx build --load \
  --build-arg AIRLOCK_ARTIFACT_IMAGE=ghcr.io/marcammann/airlock:dev \
  -f examples/daytona/soft-sandbox/Dockerfile \
  -t airlock-daytona-soft-sandbox:dev \
  examples/daytona/soft-sandbox
```

For a multi-platform registry publish, push the artifact image first and then
build the Daytona image against the pushed artifact:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f build/package/Dockerfile.artifacts \
  -t ghcr.io/marcammann/airlock:dev \
  --push \
  .

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg AIRLOCK_ARTIFACT_IMAGE=ghcr.io/marcammann/airlock:dev \
  -f examples/daytona/soft-sandbox/Dockerfile \
  -t ghcr.io/marcammann/airlock-daytona-soft-sandbox:main \
  --push \
  examples/daytona/soft-sandbox
```

By default, the pushed artifact image is:

```text
ghcr.io/marcammann/airlock:dev
```

## Reusable Snapshot

The reusable Daytona snapshot is created from the local Dockerfile:

```sh
examples/daytona/soft-sandbox/Dockerfile
```

Daytona builds that Dockerfile remotely. By default, the Dockerfile copies the
Airlock proxy worker from:

```text
ghcr.io/marcammann/airlock:dev
```

The Dockerfile also installs `litellm==1.83.7`, so LiteLLM is baked into the
reusable snapshot instead of installed in every sandbox created from it.

Push that artifact image after changing Airlock binaries:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f build/package/Dockerfile.artifacts \
  -t ghcr.io/marcammann/airlock:dev \
  --push \
  .
```

Create or reuse the snapshot from the repository root:

```sh
uv sync --project examples/daytona/soft-sandbox
DAYTONA_API_KEY=... \
  uv run --project examples/daytona/soft-sandbox \
  python examples/daytona/soft-sandbox/sandbox.py snapshot create
```

From within the example directory, the shorter form is:

```sh
DAYTONA_API_KEY=... uv run python sandbox.py snapshot create
```

The default snapshot name is:

```text
airlock-daytona-soft-sandbox-main
```

The snapshot entrypoint is:

```text
sleep infinity
```

`sandbox.py snapshot run` starts Airlock separately in a Daytona
session named `airlock-proxy`.

## Probe A Daytona Snapshot

This directory is also a small `uv` project pinned to Python 3.13 and the
Daytona Python SDK.

Create the project-level virtualenv:

```sh
cd examples/daytona/soft-sandbox
uv sync
```

Then create a sandbox from the reusable snapshot, write the secret bundle, wait
for Airlock, and inspect Daytona's process user behavior:

```sh
export DAYTONA_API_KEY=...
export OPENAI_API_KEY=...
export DAYTONA_TARGET=us
uv run python sandbox.py snapshot run
```

From the repository root, use `uv run --project examples/daytona/soft-sandbox`
with the same command if you do not want to `cd` into the example directory.

Daytona starts its own supervisor as PID 1 and treats the snapshot as a prepared
filesystem/runtime. The `snapshot run` command creates a sandbox from the
snapshot, writes `OPENAI_API_KEY=...` into the write-only secret bundle, starts
`/usr/local/bin/airlock-daytona-start-proxy` in the `airlock-proxy` session,
waits for the proxy to listen on `127.0.0.1:18080`, confirms the `daytona` user
cannot read the source bundle, Airlock-private secret, or CA key, uploads a
LiteLLM probe script through the Daytona SDK, runs an OpenAI request through
Airlock, and compares Daytona session commands, `process.exec`, and Python
`run_code` user identity.

The LiteLLM probe uses `openai/gpt-5-mini`. Customize only the prompt:

```sh
uv run python sandbox.py snapshot run --litellm-prompt "Reply with exactly: hello"
```

## Secret File Contract

The preferred boot contract is:

```text
/run/daytona-secrets/secrets.env
```

That file must exist before the Airlock proxy session starts and must not be
readable by the `daytona` user. It uses a deliberately small `KEY=value`
format, one secret per line. It is not shell-sourced, so quotes and shell
expansions are treated as literal secret value bytes.

Example:

```text
OPENAI_API_KEY=sk-...
```

In the image, it is precreated as:

```text
/run/daytona-secrets/secrets.env
owner: airlock:airlock-writers
mode: 0620
```

The Airlock starter expands each entry into an Airlock-only file by lowercasing
the key and replacing `_` with `-`. For example, `OPENAI_API_KEY` becomes:

```text
/run/airlock/secrets/openai-api-key
owner: airlock:airlock
mode: 0400
```

## Local Smoke

The smoke uses Docker, not Docker Compose, to approximate Daytona's single-image
runtime. Without `OPENAI_API_KEY`, it only checks the same-sandbox permission
boundary and Airlock startup:

```sh
examples/daytona/soft-sandbox/local-smoke.sh
```

With `OPENAI_API_KEY`, it also performs a live proxied request:

```sh
OPENAI_API_KEY=sk-... examples/daytona/soft-sandbox/local-smoke.sh
```

Both modes write the secret bundle to a temporary host file, stream it into the
container, and create `/run/daytona-secrets/secrets.env` before the Airlock
proxy starts. The proxy start script expands that bundle into Airlock's private
runtime path before serving traffic. In live mode, Airlock
terminates the local `CONNECT`, injects `Authorization: Bearer ...` from the
file-backed secret, and forwards the request upstream.

`OPENAI_API_KEY` is required for `snapshot run` because it always performs the
LiteLLM OpenAI probe. The local Docker smoke still supports the no-key
permission-only mode above.

## Running Commands In The Sandbox

The Docker image and Daytona sandbox set proxy and CA environment variables
directly. The image defaults to `sleep infinity` so local container runs can
stay alive without Airlock. `snapshot run` starts Airlock explicitly in a
Daytona session after writing the secret bundle.

Commands launched in the sandbox inherit:

```text
HTTP_PROXY=http://127.0.0.1:18080
HTTPS_PROXY=http://127.0.0.1:18080
SSL_CERT_FILE=/run/airlock/ca/ca.crt
REQUESTS_CA_BUNDLE=/run/airlock/ca/ca.crt
GIT_SSL_CAINFO=/run/airlock/ca/ca.crt
NODE_EXTRA_CA_CERTS=/run/airlock/ca/ca.crt
```

## Security Notes

This mode is useful for developer experience and for agents that run as a
non-root user. It does not prevent a privileged process inside the same sandbox
from bypassing Unix permissions or proxy environment variables.

For a hard boundary, run Airlock in a separate sidecar/container with network
policy or firewall rules that force workspace egress through Airlock.
