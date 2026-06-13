# Airlock

Airlock is a proxy-based secret management and egress control system for
workloads. Secrets are resolved and injected by the proxy-worker at the last
responsible moment; applications and the control plane never see secret values.

## Current Status

This repository is currently hardening the Kubernetes and proxy data paths
before packaging the developer workflow.

Implemented so far:

- Go control plane with Kubernetes CRD policy loading.
- Rust proxy-worker local and Envoy `ext_proc` modes; Go proxy-worker parity is
  under active buildout.
- SPIFFE mTLS between proxy-worker and control plane.
- Vault JWT-SVID login and least-privilege Vault reconciliation.
- SPIRE `ClusterSPIFFEID` reconciliation from `AirlockPolicy`.
- Manual Kubernetes sidecar data path.
- Initial mutating webhook sidecar injection.
- Split managed Envoy injection from existing Envoy integrations.
- Explicit proxy-worker runtime arguments, including local single-container
  smoke coverage.
- Initial security and failure smoke coverage for policy auth, Vault
  least-privilege access, and log redaction.
- Airlock-managed SPIRE registration cleanup for stale generated
  `ClusterSPIFFEID` objects.

## Layout

```text
control-plane/   Go module for the Airlock control plane
proxy-worker/    Go proxy-worker implementation, currently under parity buildout
proxy-worker-rs/ Rust proxy-worker implementation
proto/           shared protobuf contracts
schemas/         shared human policy schemas
fixtures/        shared cross-language policy fixtures
```

## kind Lab

The kind lab is the local integration environment. Prerequisites:

- Docker
- `kind`
- `kubectl`
- `helm`

Create the cluster and install the baseline:

```sh
make kind-up
make install-airlock
make install-vault
make deploy-demo
make test-e2e
```

Or recreate and verify the whole local lab in one command:

```sh
make demo
```

The developer workflow is split so the platform pieces can move at different
speeds:

- `make install-airlock` installs CRDs, SPIRE, the Airlock control plane, RBAC,
  and the admission webhook.
- `make install-vault` installs the local Vault dev server used by the lab.
- `make deploy-demo` applies the demo policy, provider config, echo upstream,
  proxy-worker, and sample workload.
- `make test-e2e` runs the demo, Vault, injected sidecar, existing Envoy, and
  security smokes.

This creates the core namespaces:

- `airlock-system`
- `spire-system`
- `vault`
- `demo`

The baseline currently includes:

- SPIRE server and agent in `spire-system`
- Vault dev server in `vault`
- Airlock control-plane deployment in `airlock-system`
- Airlock proxy-worker deployment in `demo`
- echo upstream service in `demo`
- `code-agent` workload in `demo`

The control plane loads policy from Kubernetes CRDs in the active demo path.

## Docker Compose Git Demo

There is also a local Compose demo for the copy-binary-into-image workflow. It
runs the Airlock control plane in one container, and a Git checkout app plus the
Airlock proxy-worker in another container under different Unix users. The app
process has no GitHub credential file access; Git reaches a private repository
through the proxy, which injects HTTPS Basic auth at the last responsible
moment.

```sh
export GITHUB_PAT=github_pat_or_classic_pat_with_repo_access
make compose-git-demo
```

Variants are available for Envoy-owned CONNECT/TLS termination and for local
policy without a control plane:

```sh
make compose-git-envoy-demo
make compose-git-no-control-plane-demo
```

See [examples/docker-compose-git](examples/docker-compose-git) for details.

## OpenCode Headless Demo

For trying OpenCode behind Airlock, there is a Compose example that runs the
OpenCode backend in Docker, routes proxy-aware outbound HTTP(S) traffic through
an Airlock proxy that allows `api.openai.com:443`, and attaches from your local
TUI:

```sh
make opencode-headless-up
make opencode-headless-attach
```

See [examples/opencode-headless](examples/opencode-headless) for the full
two-terminal flow.

## Codex App Server Demo

For trying the experimental Codex app server behind Airlock, there is a Compose
example that runs `codex app-server` in Docker, routes proxy-aware outbound
HTTP(S) traffic through an Airlock proxy that allows `api.openai.com:443` and
`chatgpt.com:443`, plus `files.openai.com:443`, and connects from your local
Codex CLI:

```sh
make codex-app-server-up
make codex-app-server-connect
```

See [examples/codex-app-server](examples/codex-app-server) for details.

## WebUI

The Airlock WebUI is a Next.js and Tailwind admin console. The first view is a
read-only policy inventory backed by the control-plane admin API:

```sh
cd web-ui
AIRLOCK_CONTROL_PLANE_URL=http://127.0.0.1:8080 npm run dev
```

See [docs/web-ui-production-plan.md](docs/web-ui-production-plan.md) for the
OIDC/OAuth, sign-up, and RBAC production plan.

## Smoke Tests

Run the local control-plane policy smoke with:

```sh
make local-control-plane-smoke
```

The smoke test starts:

- Go control plane on `127.0.0.1:18082`
- Rust proxy-worker on `127.0.0.1:18080`
- local upstream on `127.0.0.1:18081`

It verifies that the proxy-worker fetches policy from the control plane, applies
the policy to an outbound request, and emits the policy version in logs.

Run the SPIFFE-authenticated policy fetch smoke with:

```sh
make spiffe-policy-smoke
```

The smoke test verifies that an unauthenticated workload cannot fetch policy,
that the proxy-worker can fetch policy with its SVID, and that the control-plane
audit log records the proxy-worker SPIFFE identity.

The unauthenticated request below should fail:

```sh
kubectl exec -n demo deploy/code-agent -- \
  curl -kfsS --get \
  --data-urlencode 'workload_identity=spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker' \
  https://airlock-control-plane.airlock-system.svc.cluster.local:8443/v1/policies
```

Bootstrap Vault JWT auth and run the full Kubernetes egress smoke with:

```sh
make vault-jwt-setup
make k8s-egress-smoke
```

The smoke test verifies that the proxy-worker logs into Vault with its SPIFFE
identity, preloads the configured secret, injects it into an outbound request,
and redacts the secret from proxy-worker logs.

The demo `AirlockPolicy` references a `SecretProviderConfig`; the control plane
resolves Vault address, auth mount, audience, and generated role into the
compiled policy returned to the proxy-worker. The proxy-worker still obtains its
own SPIFFE JWT-SVID and reads secrets directly from Vault. The control plane
uses a Vault admin token only to write Vault ACL policies and JWT roles; it does
not read secret values.

The control plane reads `AirlockPolicy` and `SecretProviderConfig` objects from
the Kubernetes API, recompiles policy on a short reconciliation interval,
reuses the Vault reconciler, and patches `AirlockPolicy/status` when the policy
is ready.

The static manifest still grants the control plane its own bootstrap identity.
The proxy-worker `ClusterSPIFFEID` is generated from `AirlockPolicy.spec.workload`
and reconciled by the control plane.

The demo `code-agent` pod now contains the app container, an Envoy sidecar, and
the Airlock proxy-worker sidecar. The app calls Envoy on `127.0.0.1:10000`;
Envoy calls the proxy-worker through `ext_proc`; the proxy-worker fetches policy
with SPIFFE mTLS, reads Vault directly, mutates allowed requests, and denies
unmatched destinations.

Run the managed-injection sidecar smoke with:

```sh
make injected-sidecar-smoke
```

The control plane serves a Kubernetes admission webhook on port `9443`. Pods in
opted-in namespaces with `airlock.dev/enabled: "true"` and
`airlock.dev/policy: code-agent` are admitted with generated Envoy config, an
Envoy sidecar, the Airlock proxy-worker sidecar, and the SPIRE socket volume.
The smoke test proves that the source deployment is app-only while the admitted
pod gets the sidecars and still completes the same allow/deny/Vault flow.

Run the existing-Envoy and single-local smokes with:

```sh
make existing-envoy-smoke
make single-local-smoke
```

The webhook supports `airlock.dev/envoy-mode: managed` for the demo path where
Airlock injects Envoy, and `airlock.dev/envoy-mode: existing` for clusters
where Envoy is supplied by Istio, a mesh injector, or platform config. In
`existing` mode Airlock injects only the proxy-worker sidecar, SPIRE socket
volume, and SPIFFE selector label; the existing Envoy must be configured to call
the local proxy-worker `ext_proc` listener on `127.0.0.1:50051`.

The Go proxy-worker requires exactly one compact proxy selector:

- `--proxy http:builtin[@listen]`: start the builtin HTTP proxy. If `listen`
  is omitted it defaults to `127.0.0.1:18080`.
- `--proxy http:envoy[@listen]`: start the Envoy ext_proc server. If `listen`
  is omitted it defaults to `127.0.0.1:50051`.
- `--mitm-ca-cert` and `--mitm-ca-key`: enable builtin HTTPS interception for
  `CONNECT` requests by loading the Airlock MITM CA.
- `--no-control-plane`: use local `--policy` instead of fetching policy from the
  control plane.

`make single-local-smoke` starts a local upstream and a single
proxy-worker process, verifies allow/deny behavior, confirms the env secret
reaches the upstream, and checks that proxy logs redact the secret.

Run the security and fail-closed smokes with:

```sh
make security-smoke
make fail-closed-smoke
make fail-closed-k8s-smoke
```

These smokes verify unauthenticated policy fetches fail, generated Vault policy
can read only the referenced secret path, unreferenced secret reads fail,
control-plane and proxy-worker logs do not contain the Vault secret value, and
identity, policy, Vault, SDS, and secret-provider failures deny traffic by
default.

## Go Proxy-Worker Rewrite

The Go rewrite currently duplicates the Rust worker unit-test surface and adds
the first builtin HTTPS interception and Envoy ext_proc serving slices. The
covered paths include builtin HTTP proxying, `CONNECT` MITM with generated leaf
certificates, rewrite/redaction behavior, env/file secrets, local policy loading,
control-plane policy fetch, ext_proc decision logic, and the Envoy ext_proc gRPC
stream:

```sh
make test-proxy-worker
make build-proxy-worker
make proxy-worker-local-smoke
make build-proxy-worker-image
```

`make build-proxy-worker` writes a static binary to
`dist/airlock-proxy-worker`. `make build-proxy-worker-image` builds a scratch
carrier image tagged `airlock-proxy-worker:dev`, intended for the
copy-into-user-image workflow. The Go worker is the active path for builtin
proxying, Envoy ext_proc, SDS certificates, Vault-backed secrets, and the
Kubernetes smoke tests. The Rust worker is retained as `proxy-worker-rs` for
reference during the rewrite.

Example local Go worker invocation:

```sh
./dist/airlock-proxy-worker \
  --proxy http:builtin@127.0.0.1:18080 \
  --no-control-plane \
  --policy fixtures/policies/local-http.yaml
```

To intercept HTTPS `CONNECT` traffic, provide a CA whose public certificate is
trusted by the workload and whose private key is visible only to the
proxy-worker:

```sh
./dist/airlock-proxy-worker \
  --proxy http:builtin@127.0.0.1:18080 \
  --mitm-ca-cert .airlock/ca.crt \
  --mitm-ca-key .airlock/ca.key \
  --no-control-plane \
  --policy fixtures/policies/local-http.yaml
```

The Go worker can also serve Envoy ext_proc locally:

```sh
./dist/airlock-proxy-worker \
  --proxy http:envoy@127.0.0.1:50051 \
  --no-control-plane \
  --policy fixtures/policies/local-http.yaml
```

In Envoy mode, Envoy can remain the TLS terminator while the proxy-worker
provides SDS certificates alongside ext_proc policy decisions. The current smoke
coverage includes direct Envoy TLS termination and explicit `CONNECT` MITM:

```sh
make envoy-sds-tls-smoke
make envoy-connect-sds-smoke
```

Secret provider code is split by responsibility under
`proxy-worker/internal/worker`. See
[`docs/contributing/secret-providers.md`](docs/contributing/secret-providers.md)
for the provider layout and the checklist for adding a backend.

## Local Proxy-Worker

The Rust worker still has the original local HTTP proxy mode:

```sh
cd proxy-worker-rs
cargo run -p airlock-proxy-worker -- \
  --no-control-plane \
  --policy ../fixtures/policies/local-http.yaml \
  --listen 127.0.0.1:18080
```

The Rust local mode supports plain HTTP forwarding, egress allow/deny checks,
env/file secret resolution, header rewrites, and redacted event logs. The Go
worker is now the path for builtin HTTPS interception work.

## Envoy ext_proc

The Envoy `ext_proc` gRPC server uses the same policy, secret, rewrite, and
redaction logic as local proxy mode. The Rust worker has the original
implementation, and the Go worker now has a parity ext_proc server:

```sh
./dist/airlock-proxy-worker \
  --proxy http:envoy@127.0.0.1:50051 \
  --no-control-plane \
  --policy fixtures/policies/local-http.yaml
```

A local Envoy config is available at `deploy/envoy/ext-proc-local.yaml`. It
expects:

- proxy-worker ext_proc server on `127.0.0.1:50051`
- upstream HTTP service on `127.0.0.1:18081`
- Envoy listener on `127.0.0.1:10000`

## Checkpoints

Run the contract and proxy package checks:

```sh
cd control-plane && go test ./...
cd proxy-worker-rs && cargo test --workspace
```

The Go and Rust packages both load the same policy fixtures and enforce the
initial validation rules:

- wildcard secret paths are rejected
- unknown secret providers are rejected
- egress rules require a host
- unsafe Vault paths under `sys/` or `auth/` are rejected
