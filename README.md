# Airlock

Airlock is a proxy-based egress control and secret injection system for
workloads. Applications send outbound traffic through an Airlock proxy worker;
the worker enforces policy, resolves secrets at the last responsible moment, and
keeps secret values out of application containers and the control plane.

Airlock is currently a development-stage project. The active implementation is
the Go control plane plus the Go proxy worker.

## What Is Here

- Kubernetes CRDs for `AirlockPolicy`, `AirlockWorkload`, and
  `SecretProviderConfig`.
- Go control plane with file and Kubernetes policy loading.
- SPIFFE mTLS between proxy workers and the control plane.
- SPIRE `ClusterSPIFFEID` reconciliation from Airlock workloads.
- Vault JWT-SVID login and least-privilege Vault policy/role reconciliation.
- Go proxy worker with builtin HTTP proxying, HTTPS `CONNECT` interception,
  Envoy `ext_proc`, SDS certificate serving, and secret redaction.
- Mutating webhook support for managed Envoy injection and existing-Envoy
  deployments such as Istio-style sidecars.
- Next.js WebUI with read-only workload inventory, workload detail pages, and a
  proxy status surface ready for heartbeat data.
- Docker Compose demos for Git, OpenCode, and Codex app-server workflows.

## Repository Layout

```text
control-plane/    Go control plane and Kubernetes reconcilers
proxy-worker/     Go proxy worker, the active worker implementation
web-ui/           Next.js and Tailwind admin console
deploy/           kind, Kubernetes, Envoy, and Helm assets
examples/         Docker Compose, Kubernetes, and integration examples
fixtures/         shared policy and provider fixtures
proto/            protobuf contracts
schemas/          policy schema files
scripts/          local and Kubernetes smoke tests
docs/             design notes and contributor guides
```

## Quick Start

Run the unit and package checks:

```sh
make test
```

Build the active proxy worker:

```sh
make build-proxy-worker
```

The binary is written to:

```text
dist/airlock-proxy-worker
```

Build container images:

```sh
make build-images
make build-web-ui-image
```

## Local Proxy Worker

The Go worker accepts one compact proxy selector:

```text
--proxy http:builtin[@listen]
--proxy http:envoy[@listen]
```

Current defaults:

- `http:builtin` listens on `127.0.0.1:18080`.
- `http:envoy` listens on `127.0.0.1:50051`.
- `--no-control-plane` loads a local compiled policy from `--policy`.

Run a local builtin proxy:

```sh
make build-proxy-worker
./dist/airlock-proxy-worker \
  --proxy http:builtin@127.0.0.1:18080 \
  --no-control-plane \
  --policy fixtures/compiled/local-http.yaml
```

Enable builtin HTTPS interception by giving the worker a CA certificate and key.
The workload must trust the CA certificate; the private key should only be
visible to the proxy worker.

```sh
./dist/airlock-proxy-worker \
  --proxy http:builtin@127.0.0.1:18080 \
  --mitm-ca-cert .airlock/ca.crt \
  --mitm-ca-key .airlock/ca.key \
  --no-control-plane \
  --policy fixtures/compiled/local-http.yaml
```

Run the Envoy integration locally:

```sh
./dist/airlock-proxy-worker \
  --proxy http:envoy@127.0.0.1:50051 \
  --no-control-plane \
  --policy fixtures/compiled/local-http.yaml
```

Envoy config for local testing is in
[`deploy/envoy/ext-proc-local.yaml`](deploy/envoy/ext-proc-local.yaml).

## Kubernetes kind Lab

The kind lab is the main integration environment.

Prerequisites:

- Docker
- `kind`
- `kubectl`
- `helm`

Create the cluster, install Airlock and Vault, deploy the demo, and run the core
smokes:

```sh
make demo
```

Or run the steps manually:

```sh
make kind-up
make install-airlock
make install-vault
make deploy-demo
make test-e2e
```

The lab creates these namespaces:

- `airlock-system`
- `spire-system`
- `vault`
- `demo`

The demo path includes the control plane, SPIRE, Vault, an echo upstream, an
Airlock proxy worker, and the `code-agent` workload.

Reusable Airlock installation assets live in `deploy/k8s`. Runnable Kubernetes
scenarios live under [`examples/k8s`](examples/k8s):

- [`basic-egress`](examples/k8s/basic-egress): standalone proxy worker, Envoy,
  echo upstream, and workload/policy resources.
- [`injected-sidecar`](examples/k8s/injected-sidecar): webhook-managed Envoy
  and proxy worker injection.
- [`existing-envoy`](examples/k8s/existing-envoy): app-owned Envoy with only
  the proxy worker injected.

## Kubernetes Data Paths

Airlock supports two Kubernetes sidecar shapes:

- Managed Envoy: Airlock injects Envoy and the proxy worker.
- Existing Envoy: Airlock injects only the proxy worker and SPIRE socket volume;
  an existing Envoy sidecar calls the local `ext_proc` listener.

Run the Kubernetes smokes:

```sh
make spiffe-policy-smoke
make vault-jwt-setup
make k8s-egress-smoke
make injected-sidecar-smoke
make existing-envoy-smoke
```

Run fail-closed and TLS/SDS coverage:

```sh
make security-smoke
make fail-closed-smoke
make fail-closed-k8s-smoke
make tls-termination-smoke
make envoy-sds-tls-smoke
make envoy-connect-sds-smoke
```

## Docker Compose Demos

### Git Checkout

The Git demo runs the control plane in one container and an app plus Airlock
proxy worker in another. The app runs as an unprivileged user and does not have
direct access to GitHub credentials; the proxy injects HTTPS Basic auth.

```sh
export GITHUB_PAT=github_pat_or_classic_pat_with_repo_access
make compose-git-demo
```

Variants:

```sh
make compose-git-envoy-demo
make compose-git-no-control-plane-demo
```

See [`examples/compose/git`](examples/compose/git).

### Proxy Observability

The proxy observability demo keeps the control plane, proxy worker, Web UI, and
curl client in separate containers. Use it when you want to watch heartbeats and
allow/deny counters without a one-shot app container exiting.

```sh
make compose-proxy-observability-up
```

Then open `http://127.0.0.1:13000/proxies` and run curl requests from the
client container.

See [`examples/compose/proxy-observability`](examples/compose/proxy-observability).

### OpenCode

The OpenCode example runs a headless OpenCode server in Docker and routes
proxy-aware HTTP(S) egress through Airlock.

```sh
make opencode-headless-up
make opencode-headless-attach
```

See [`examples/compose/opencode-headless`](examples/compose/opencode-headless).

### Codex App Server

The Codex app-server example runs `codex app-server` in Docker and connects
from the local Codex CLI.

```sh
make codex-app-server-up
make codex-app-server-connect
```

See [`examples/compose/codex-app-server`](examples/compose/codex-app-server).

## WebUI

The WebUI is a Next.js and Tailwind admin console. It currently exposes:

- read-only workload inventory
- read-only workload detail pages
- proxy status page backed by the control-plane admin API
- proxy detail pages with rolling allow, deny, and proxy error counters

Run it locally against a control-plane admin listener:

```sh
cd web-ui
AIRLOCK_CONTROL_PLANE_URL=http://127.0.0.1:18089 \
AIRLOCK_CONTROL_PLANE_TOKEN="$OIDC_ACCESS_TOKEN" \
AIRLOCK_WEB_AUTH_MODE=oidc \
AIRLOCK_WEB_SESSION_SECRET="$(openssl rand -base64 32)" \
AIRLOCK_WEB_OIDC_ISSUER=https://issuer.example.test \
AIRLOCK_WEB_OIDC_CLIENT_ID=airlock-web \
AIRLOCK_WEB_OIDC_CLIENT_SECRET=... \
npm run dev
```

The control plane splits worker and admin auth. Workers should use the worker
listener with SPIFFE mTLS. The WebUI should use an admin listener configured
with OIDC bearer validation and RBAC, for example
`--worker-auth=spiffe --admin-listen=:8081 --admin-auth=oidc`.

The WebUI is its own browser auth boundary. Its API routes and server-rendered
pages require a signed WebUI session before the server uses
`AIRLOCK_CONTROL_PLANE_TOKEN` to call the control-plane admin API.

Production planning for OIDC/OAuth, sign-up, RBAC, proxy status, and audit
surfaces lives in
[`docs/web-ui-production-plan.md`](docs/web-ui-production-plan.md).

Proxy heartbeat and OTEL audit design lives in
[`docs/proxy-status-and-audit-telemetry.md`](docs/proxy-status-and-audit-telemetry.md).

## Secret Providers

Vault is the first secret provider. The control plane combines
`AirlockWorkload`, referenced `AirlockPolicy` objects, and
`SecretProviderConfig` into one compiled policy per workload, then reconciles
Vault ACL policy and JWT roles. The proxy worker obtains its own SPIFFE JWT-SVID
and reads secrets directly from Vault; the control plane does not read secret
values.

`SecretProviderConfig` is namespaced. A workload `secretProviderRef` without an
explicit namespace resolves in the workload namespace, so each environment can
define its own `SecretProviderConfig/default` while sharing the same policies
and workload manifests. Vault defaults can set `pathPrefix` to map logical
policy paths such as `github/token` to environment-specific paths such as
`prod/github/token`.

Secret provider code is split by responsibility under
`proxy-worker/internal/worker`. See
[`docs/contributing/secret-providers.md`](docs/contributing/secret-providers.md)
for the provider layout and contribution checklist.

## Useful Checks

```sh
make test
make test-proxy-worker
make test-web-ui
make proxy-worker-local-smoke
make single-local-smoke
make local-control-plane-smoke
```

The current checks cover policy validation, control-plane auth, proxy allow/deny
behavior, secret redaction, Vault access boundaries, Envoy `ext_proc`, SDS, and
fail-closed behavior.
