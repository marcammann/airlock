# Airlock Project Specification

## Summary

Airlock is a proxy-based egress control and secret injection system for
workloads that need outbound access to sensitive services without receiving
long-lived credentials directly.

The project is designed for agentic, automation-heavy, and sandboxed workloads
where application code may need to call external APIs, clone repositories, or
reach internal systems, but should not be trusted with the raw secrets required
to do so. Applications route outbound traffic through an Airlock proxy worker.
The proxy worker enforces an allowlist policy, resolves secrets at the last
responsible moment, rewrites requests, redacts sensitive data from logs, and
fails closed when policy or secrets are unavailable.

Airlock is currently a development-stage project. The active implementation is
the Go control plane, Go proxy worker, Kubernetes policy model, Docker Compose
examples, Daytona soft-sandbox example, and Next.js admin console.

## Problem Statement

Modern automation workloads increasingly run third-party or generated code in
containers, Kubernetes pods, sandboxes, CI jobs, and developer environments.
Those workloads often need privileged egress:

- LLM APIs such as OpenAI, Anthropic, OpenRouter, or Google AI.
- Git hosting APIs and HTTPS Git clone/fetch operations.
- Internal HTTP APIs.
- Databases and infrastructure services.
- Secret-backed SaaS APIs with scoped credentials.

The common pattern is to inject API keys or tokens directly into the workload
environment. That is simple, but it gives the application full access to the
credential. Any bug, prompt injection, code execution path, dependency, or
misconfigured log line can read and exfiltrate it.

Airlock changes the boundary:

- The workload sees a proxy endpoint and trust material, not the raw secret.
- The proxy sees policy and secrets, but only uses them to modify approved
  outbound requests.
- The control plane compiles and serves policy, but does not read secret values.
- Secret providers remain the source of truth for secret values.

The result is a practical middle ground between "give the container all the
secrets" and "build a custom broker for every API."

## Primary Goals

1. Keep secrets out of application containers.

   Workloads should not receive API keys, PATs, OAuth tokens, or Vault tokens
   when those values can be held by the proxy worker instead.

2. Enforce default-deny egress.

   Outbound requests should be denied unless they match an explicit policy
   rule for scheme, host, port, and eventually method/path where applicable.

3. Inject credentials only into allowed requests.

   Credential rewrites should happen inside the proxy worker, immediately
   before forwarding an allowed request upstream.

4. Fail closed.

   Missing policy, missing secrets, secret provider failures, invalid identity,
   malformed requests, and unsupported proxy modes should deny traffic rather
   than falling back to direct egress.

5. Separate control-plane, admin, and worker trust.

   Worker policy APIs, admin APIs, enrollment APIs, and browser UI sessions are
   different security surfaces and must remain separate.

6. Support Kubernetes and non-Kubernetes deployments.

   Kubernetes should use CRDs, SPIFFE/SPIRE, Vault, admission webhook injection,
   and Envoy integration. Non-Kubernetes environments should support local
   policy files, Docker Compose, and copy-the-binary sandbox workflows.

7. Make the contributor model clear.

   Secret providers, proxy modes, policy compilation, control-plane auth, and
   UI surfaces should have clear ownership boundaries so new contributors can
   add functionality without editing unrelated code.

8. Make operations visible without becoming a log database.

   The control plane should expose current proxy status and recent denied/error
   events. Full request history should live in OTEL, Prometheus, ClickHouse,
   Loki, or another operator-owned telemetry backend.

## Non-Goals

Airlock is not intended to be:

- A general service mesh.
- A full SIEM, log database, or durable audit store.
- A replacement for Vault, cloud secret managers, or identity providers.
- A transparent host firewall.
- A universal protocol proxy on day one.
- A browser-facing identity provider.
- A system that guarantees hard isolation when proxy and workload run in the
  same Unix/container boundary.

Some deployment modes, especially the Daytona soft-sandbox example, are soft
boundaries intended to improve developer experience. Stronger isolation should
use separate containers, pods, network namespaces, sidecars, SPIFFE identities,
and least-privilege secret provider credentials.

## Core Concepts

### AirlockPolicy

`AirlockPolicy` is a reusable egress policy. It contains named egress rules.
Each rule describes an allowed destination and optional request rewrites.

Current rule shape:

- `scheme`
- `host`
- `port`
- zero or more header rewrite rules
- source policy metadata after compilation

Policies are reusable. Multiple workloads can reference the same policy.

### AirlockWorkload

`AirlockWorkload` assigns one or more policies to a workload identity. The
control plane compiles a single effective policy for each workload.

Current workload shape:

- workload identity, primarily SPIFFE ID in Kubernetes
- namespace and service account metadata
- one or more policy references
- optional secret provider reference

The proxy worker receives the compiled policy for its workload and never needs
to reason about multiple policy objects at request time.

### SecretProviderConfig

`SecretProviderConfig` configures the secret backend for a namespace or
environment. A workload can reference a provider explicitly, or resolve a
default provider in its namespace.

The first supported remote provider is Vault. Vault configuration includes:

- Vault address
- JWT auth mount
- JWT audience
- generated role
- optional defaults for mount, engine, and path prefix

This lets organizations share policies across environments while changing only
the provider configuration. For example, the same logical secret path can map
to different Vault prefixes in `dev`, `staging`, and `prod`.

### Compiled Policy

The control plane compiles `AirlockWorkload`, referenced `AirlockPolicy`
objects, and `SecretProviderConfig` into one `CompiledPolicy` per workload.

The compiled policy is the worker contract. It contains:

- policy version
- workload identity
- effective egress rules
- resolved source policy metadata
- resolved secret provider configuration

The control plane serves compiled policy to workers. The proxy worker enforces
compiled policy.

### Proxy Worker

The proxy worker is the runtime enforcement point. It:

- loads compiled policy from a local file or the control plane
- accepts outbound proxy traffic
- denies unmatched requests
- resolves secrets from local env/file providers or remote providers
- rewrites allowed requests
- redacts sensitive values from logs
- reports heartbeats and denied/error summaries

Current proxy modes:

- `http:builtin`: builtin HTTP proxy with HTTP and HTTPS CONNECT interception.
- `http:envoy`: Envoy `ext_proc` integration for Envoy-owned data paths.

Planned protocol families can use the same `--proxy protocol:mode[@listen]`
shape, for example `git:builtin` or database-specific integrations.

### Control Plane

The control plane is responsible for policy state, compilation, admin APIs,
worker policy APIs, enrollment, optional reconciliation, and recent proxy
status.

It can load policy from:

- static files
- Kubernetes resources

It can reconcile supporting systems:

- SPIRE `ClusterSPIFFEID` resources
- Vault ACL policies and JWT roles

It exposes separate surfaces:

- worker API for policy fetch, heartbeat, event ingest, and enrollment redeem
- admin API for read-only console data and future operations
- optional health listener
- optional admission webhook listener

### Enrollment

Enrollment is the bootstrap path for environments that do not use SPIFFE for
worker authentication.

Flow:

1. A dispatcher authenticates to the enrollment endpoint.
2. The control plane mints a short-lived one-time enrollment token for a
   specific workload.
3. The proxy worker redeems that token.
4. The control plane returns the compiled policy.

Enrollment tokens are not long-lived worker credentials. Durable worker auth is
expected to use SPIFFE or a future explicitly designed credential mechanism.

### Insecure Mode

`--insecure` exists for local development and smoke tests.

On the control plane, it allows auth mode `none` and defaults unspecified
worker/admin auth to `none`.

On the proxy worker, it fetches policy, sends heartbeats, and reports events
without authenticating to the control plane.

`--insecure` must not be treated as production auth. It should be explicit,
loud, and easy to spot in examples and logs.

## Architecture

```text
Workload
  -> HTTP proxy settings or Envoy sidecar
  -> Airlock proxy worker
  -> approved upstream service

Airlock proxy worker
  -> control plane worker API for compiled policy
  -> secret provider for secret values
  -> control plane heartbeat/event endpoints

Airlock control plane
  -> file or Kubernetes policy source
  -> optional SPIRE reconciliation
  -> optional Vault reconciliation
  -> admin API for WebUI

Airlock WebUI
  -> OIDC/OAuth browser login
  -> server-side control-plane admin client
```

The control plane does not sit in the data path. Request-time enforcement is in
the proxy worker.

## Deployment Modes

### Local Standalone

The proxy worker runs without a control plane and loads a compiled policy from
disk. This is the smallest mode for local development, Docker Compose, and
copy-the-binary sandbox workflows.

Use cases:

- local OpenCode or Codex server experiments
- Daytona soft-sandbox images
- quick policy and rewrite testing
- single-container workflows where soft isolation is acceptable

### Control Plane With Enrollment

The control plane serves compiled policy, and a dispatcher creates a short-lived
enrollment token for a worker. The proxy worker redeems the token and then
serves traffic.

Use cases:

- non-Kubernetes runners
- CI jobs
- external sandbox dispatchers
- environments that cannot use SPIFFE yet

### Kubernetes With SPIFFE

Workers authenticate to the control plane using SPIFFE mTLS. The control plane
can load CRDs, reconcile SPIRE resources, reconcile Vault roles/policies, and
serve compiled policy to the worker.

Use cases:

- production Kubernetes
- multi-workload deployments
- Vault-backed secrets
- strict identity and policy separation

### Envoy Data Path

Envoy owns the downstream proxy listener and calls the Airlock proxy worker via
`ext_proc`. Airlock can support managed Envoy injection or work with existing
Envoy deployments such as Istio-style sidecars.

Use cases:

- organizations already standardizing on Envoy
- TLS termination controlled by Envoy
- sidecar data paths with operational Envoy tooling

## Security Model

### Trust Boundaries

Airlock assumes these components have different trust levels:

- application/workload code: least trusted
- proxy worker: trusted to enforce policy and hold runtime secrets
- secret provider: source of truth for secret values
- control plane: trusted to compile and distribute policy, not to hold secret
  values
- WebUI: browser-facing admin surface with its own session boundary

### Secret Handling

Secret values should:

- never be returned by the control-plane admin API
- never be logged by the proxy worker
- never be present in policy objects
- only be resolved by the proxy worker or secret provider
- be injected only into allowed requests

Secret references and paths may be operational metadata, but they still need
careful redaction in UI and logs because some organizations treat path names as
sensitive.

### Identity

Production worker identity should prefer SPIFFE/SPIRE. A worker should only be
able to fetch the policy for its own workload identity.

Admin identity should use OIDC/OAuth and RBAC. The browser should never receive
raw control-plane service credentials. The WebUI should enforce its own session
boundary and call the control plane from the server side.

Enrollment identity is dispatcher identity, not worker identity. Enrollment
auth decides who can mint a token for which workload.

### Fail-Closed Requirements

The proxy worker must deny or fail startup when:

- policy cannot be loaded
- policy is invalid
- a destination has no matching egress rule
- a required secret cannot be resolved
- a secret provider cannot authenticate
- control-plane policy fetch fails before startup
- SPIFFE or enrollment auth fails
- an unsupported proxy mode is requested

The control plane must reject:

- unauthenticated worker/admin requests unless explicitly insecure
- malformed policy, workload, and provider configs
- enrollment requests outside the caller's grants
- event ingestion beyond configured rate limits

## Policy Model Goals

The policy model should remain simple and composable:

- policies are reusable allowlists
- workloads assign policies
- the control plane computes one effective policy per workload
- environment-specific secret backend config lives in `SecretProviderConfig`
- CRD/file-managed resources are read-only in the admin UI
- database-backed mutable resources may come later, but are not required now

Future policy extensions should be evaluated against operational clarity. Route
matching by method/path, Git-specific behavior, database proxying, or OIDC token
exchange should extend the model without making simple HTTP allowlists harder
to read.

## Observability Goals

Airlock should expose enough data for operators to answer:

- Which workloads exist?
- Which policies are assigned?
- Which proxy instances are currently active?
- When did a proxy last fetch policy?
- When did a proxy last heartbeat?
- What was recently denied or errored?
- Which source policy and egress rule allowed a request?

The control plane should keep only bounded recent event state. Full allowed
request history belongs in external telemetry systems.

Current intended split:

- control plane: current proxy status and recent denied/error event summaries
- proxy worker: structured decision logs and optional event reports
- OTEL/metrics backend: long-term request decision history
- WebUI: read-only operator view over control-plane status and future external
  telemetry

## WebUI Goals

The Airlock Console should be an operational console, not the source of truth
for CRD/file-managed policy.

Near-term UI goals:

- read-only policies list
- read-only policy detail
- read-only workloads list
- workload detail with assigned policies and effective egress
- proxy instances under workloads
- proxy detail with recent allow, deny, and proxy error counters
- OIDC/OAuth login and session handling
- RBAC-aware admin surfaces

Future UI goals:

- secret provider visibility without secret values
- audit/event browsing with pagination
- ClickHouse/Loki/OTEL-backed long-term telemetry
- mutable database-backed policies if Airlock adds a database source
- policy review and approval workflow

## Secret Provider Goals

Vault is the first remote provider. The provider model should allow additional
backends without disturbing proxy policy enforcement.

Provider requirements:

- fail closed on errors
- preload or validate references where possible
- keep request-time resolution deterministic and fast
- separate provider config from policy where practical
- redact values in every log path
- test validation, selection, resolution, and redaction

Potential future providers:

- AWS Secrets Manager
- GCP Secret Manager
- Azure Key Vault
- Kubernetes Secrets for local cluster demos
- OIDC token exchange providers for APIs that do not use static keys

## Proxy and Protocol Goals

Current focus is HTTP and HTTPS egress. Future proxy families should preserve
the same enforcement principles:

- default deny
- policy match before connection
- secret injection only after allow
- no raw credentials in the workload
- structured redacted telemetry

Potential future proxy modes:

- `git:builtin` for HTTPS Git-specific credential handling
- database adapters such as PostgreSQL via PgBouncer-style integration
- OIDC exchange helpers for APIs that require short-lived bearer tokens
- Redis-backed or local leaky-bucket rate limiting for egress

HTTP should remain the primary production path until non-HTTP protocols have
clear policy and operational models.

## Kubernetes Goals

Kubernetes support should feel native:

- CRDs for policy, workload, and secret provider config
- namespaces as the environment boundary
- SPIFFE identities for workers and control plane
- SPIRE reconciliation from Airlock workload intent
- Vault role/policy reconciliation from workload intent
- admission webhook support for managed sidecars
- existing-Envoy support for Istio-style deployments
- status updates that show SPIRE/Vault readiness

The control plane can run per environment/namespace or per cluster depending on
operator preference. The spec favors namespaced `SecretProviderConfig` so the
same policy/workload intent can be reused across environments while secret
backend configuration changes per namespace.

## Packaging Goals

Airlock should be easy to consume in several forms:

- Kubernetes manifests and Helm-compatible assets
- standalone proxy worker binary
- container images for control plane, proxy worker, and WebUI
- scratch artifact image containing Airlock binaries
- Docker Compose examples
- Daytona-compatible sandbox image

The proxy worker binary should be copyable into another image in the same style
as tools like `uv`, without forcing users to inherit from an Airlock base image.

## Repository Boundaries

Current package ownership:

- `api/`: public Go API and wire contract types
- `cmd/`: binary entrypoints
- `internal/controlplane/`: policy store, admin/worker APIs, auth, enrollment,
  Kubernetes source, SPIRE reconciliation, Vault reconciliation, webhook
- `internal/policy/`: policy type aliases and compiler behavior
- `internal/proxyworker/`: proxy runtime, Envoy integration, policy providers,
  secret providers, telemetry, MITM CA handling
- `web-ui/`: Next.js admin console
- `examples/`: runnable Compose, Kubernetes, and Daytona examples
- `docs/`: design notes and contribution guides

New code should stay within the closest existing boundary. Shared logic should
be promoted only when it is genuinely used across packages.

## Implementation Baseline

Current Go implementation choices:

- builtin HTTP proxying uses `elazarl/goproxy` for HTTP proxy handling,
  CONNECT tunneling, and HTTPS MITM interception
- Kubernetes loading and reconciliation use `controller-runtime` clients,
  managers, watches, status patches, and optional leader election
- Vault integration uses `hashicorp/vault/api` for worker KV-v2 reads and
  control-plane ACL policy/JWT role reconciliation
- admin OIDC validation uses `coreos/go-oidc` with `golang-jwt/jwt` in tests
- HTTP routing uses `go-chi/chi`
- runtime logging uses `log/slog`
- metrics use `prometheus/client_golang`
- tracing uses OpenTelemetry HTTP and gRPC instrumentation
- binary configuration is parsed with `envconfig` plus explicit CLI flags
- tests use `testify` where it improves readability

Workers support live policy reload. Control-plane policy providers use ETags
and conditional fetches, and builtin/Envoy paths swap compiled policies through
atomic pointers so a request uses one policy snapshot while later requests see
the newer policy.

Admin APIs are a separate listener surface from worker APIs. Plain HTTP admin
serving requires explicit `--insecure`; production-style admin serving should
use `--admin-tls-cert` and `--admin-tls-key` with authentication and RBAC from
the auth configuration.

## Quality Bar

Airlock should maintain tests for:

- policy validation and compilation
- workload/policy assignment
- secret provider selection and redaction
- proxy allow/deny behavior
- fail-closed behavior
- SPIFFE mTLS policy fetch
- enrollment create/redeem
- control-plane admin and worker auth separation
- heartbeat and event ingest
- Envoy `ext_proc`
- SDS and TLS interception
- Kubernetes source loading and reconciliation
- Vault reconciliation and Vault provider behavior
- WebUI auth boundary and route protection

Smoke tests should exercise both local and Kubernetes workflows. Docker Compose
examples should remain small, named by logical scenario, and runnable without
Makefile wrappers.

## Near-Term Milestones

1. Stabilize the Go control plane and proxy worker CLI.
2. Keep the three canonical Compose examples healthy:
   `standalone`, `control-plane-enrollment`, and `spiffe-envoy`.
3. Harden worker/control-plane auth defaults around SPIFFE and explicit
   `--insecure`.
4. Finish read-only WebUI policy, workload, proxy, and event views.
5. Keep policy CRDs split between reusable `AirlockPolicy` and assigned
   `AirlockWorkload`.
6. Improve event/OTEL integration while keeping control-plane event storage
   bounded.
7. Expand secret provider contribution patterns and tests.
8. Continue Kubernetes hardening around injected sidecars, existing Envoy, SDS,
   and Vault.

## Future Milestones

1. Durable admin auth model with production OIDC/OAuth and RBAC.
2. Optional identity-broker model where WebUI forwards Airlock-scoped user
   tokens to the control plane.
3. Database-backed policy source for mutable UI-managed resources.
4. Git HTTPS proxy behavior that keeps Git credentials out of agent processes.
5. Builtin egress rate limiting.
6. OIDC token exchange support for provider APIs that need scoped short-lived
   tokens.
7. Additional secret providers.
8. External telemetry backend integration for long-term decision history.
9. Helm chart and production deployment documentation.
10. Versioned API compatibility policy when the project moves beyond
    `v1alpha1`.

## Open Design Questions

- Should enrollment mint durable worker credentials, or remain only a policy
  bootstrap mechanism?
- Which external telemetry backend should be the first supported console
  integration: ClickHouse, Loki, Elasticsearch, Honeycomb, or another OTEL
  destination?
- What is the right minimal Git HTTPS proxy scope before supporting SSH?
- How should Airlock represent method/path matching without making policy
  authoring too complex?
- Should mutable policies require a database backend only, leaving CRD/file
  sources permanently read-only?
- What should the first non-Vault secret provider be?
- What guarantees should Airlock document for soft sandbox modes where workload
  and proxy share a container boundary?

## Success Criteria

Airlock is successful when an operator can:

- define reusable egress policies
- assign those policies to workloads
- run proxy workers without exposing secrets to workload code
- prove denied traffic is blocked
- prove allowed traffic receives only the intended injected credentials
- rotate or change secrets in the backend without changing application images
- see active proxies and recent denied/error events in the console
- use SPIFFE/Vault/Kubernetes in production-like deployments
- use standalone binary or Compose workflows for local development
- extend secret providers and proxy modes without destabilizing the core
  security model
