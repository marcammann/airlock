# REFACTOR.md — Airlock Cleanup Plan

## Scope and Decisions

This refactor addresses security, correctness, structural, and idiomatic issues
surfaced in the proxy worker (`internal/proxyworker/`, `cmd/airlock-proxy-worker/`)
and the control plane (`internal/controlplane/`, `internal/policy/`,
`cmd/airlock-control-plane/`).

The software is pre-release; **no backwards compatibility is preserved**. Old
flags, old log formats, old HTTP shapes, and old package paths may be removed
freely.

The following directional decisions are baked into the plan:

- **HTTP proxy library**: adopt `elazarl/goproxy` as part of this refactor.
  Removes the hand-rolled parser, MITM plumbing, and the
  single-request-per-CONNECT bug. Keep the change mechanically isolated enough
  to revert if needed, but do not defer it to a later compatibility phase.
- **Kubernetes client**: migrate to `sigs.k8s.io/controller-runtime`. Removes
  ~600 LOC of hand-rolled list/patch/delete and adds watch, conflict retry,
  leader election, and typed CRD clients.
- **Package layout**: split files and extract leaf packages after P0/P1 fixes,
  not before. Go package extraction is not a pure move once handlers need access
  to shared state; avoid import churn until the security and correctness fixes
  are landed.
- **Worker live reload**: in scope. Adds `atomic.Pointer[CompiledPolicy]`,
  control-plane polling, and reload tests.
- **Admin TLS**: add `--admin-tls-cert` / `--admin-tls-key`; plain-HTTP admin
  requires explicit `--insecure`.

Reference docs: `SPEC.md`. All file paths and line numbers in this plan are
anchored to the current tree and will drift as commits land; re-resolve with
`grep`/`rg` before each sprint.

---

## Execution Order

1. **Sprint 0 — P0 security fixes** (small, isolated guards + regression tests)
2. **Sprint 1 — P1 correctness/runtime** (compiler purity, shutdown, timeouts, unbounded
   maps, rate limits, admin TLS)
3. **Sprint 2 — Structural prep** (same-package file split, leaf package extraction,
   lint baseline)
4. **Sprint 3 — Builtin proxy swap + worker live reload** (`goproxy`,
   `atomic.Pointer`, policy polling, reload tests)
5. **Sprint 4 — Library and observability swaps** (`controller-runtime`,
   `vault/api`, `coreos/go-oidc`, `chi`, `slog`, prometheus, otel, envconfig,
   testify)
6. **Sprint 5 — Hygiene** (doc comments, dedup, error strings, test fixtures,
   test gaps)

Each sprint is independently mergeable. Sprints do not depend on later sprints.

---

## Sprint 0 — P0 Security Fixes

Each item is a small, isolated guard with a regression test. Land these before
broad package moves so fixes are easy to review, bisect, and back out.

### 0.1 Header injection via CRLF in secret values

**Files**: `internal/proxyworker/builtin/rewrite.go` (was `rewrite.go:54-68`),
`builtin/proxy.go:340`.

**Change**: in `ApplyRewrites`, after substituting `{{secret}}`, validate the
resulting value with `strings.ContainsAny(value, "\r\n")` → return a
`ValidationError` ("rewrite value contains CRLF"). The caller must fail the
request (502 / ext_proc immediate error) rather than emit the header.

**Test**: `TestRewriteRejectsCRLFInSecretValue` — feed a secret containing
`foo\r\nX-Evil: bar`, assert no header is emitted and the request is denied.

### 0.2 Vault path traversal

**Files**: `internal/proxyworker/secrets/vault_client.go:65`, `types.go:108`
(`isUnsafeVaultPath`).

**Change**: in `vaultReadKV2`, compute `cleaned := path.Clean(path)`; reject if
`cleaned == ".."`, starts with `../`, or contains a `..` segment. Re-run
`isUnsafeVaultPath` on `mount + "/" + cleaned`. Apply the same to the
control-plane reconciler in `reconcile/vault_reconciler.go` when constructing
ACL policy paths.

**Test**: `TestVaultRejectsTraversalPath` with `path: "../../sys/raw/secret"`,
`path: "auth/foo"`, `path: "foo/../bar"`.

### 0.3 Unbounded upstream response read

**Files**: `internal/proxyworker/builtin/proxy.go:246`.

**Change**: remove unbounded `io.ReadAll(upstream)`. If `Content-Length` is
known and exceeds `maxResponseBytes`, reject before forwarding the body. For
buffered paths, read through a counting `LimitReader` that can detect overflow.
For streaming responses, preserve streaming behavior while counting bytes and
closing the upstream/client connection when the configured cap is exceeded.
`maxResponseBytes` defaults to 16 MiB and is configurable via
`--max-response-bytes`. On overflow, log
`denied proxy_error reason=response_too_large`.

**Test**: `TestUpstreamResponseOverLimitIsRejected` — upstream returns 32 MiB;
assert the proxy terminates the response without unbounded buffering or OOM.

### 0.4 Timeouts and context on the builtin proxy

**Files**: `internal/proxyworker/builtin/proxy.go` (`HandleClient:68`,
`handleConnect:88`, `tunnelConnect:151`, `forwardRequest:189`,
`dialUpstream:254`).

**Change** (will be largely absorbed by the Sprint 3 `goproxy` migration, but
land safety now):

- Add `context.Context` parameter to `HandleClient`, threaded from `Serve`
  (which wraps `listener.Accept()` goroutines in
  `context.WithCancel(parentCtx)`).
- `dialUpstream` uses `(&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, ...)`.
- `tunnelConnect` propagates context; on `ctx.Done()` it closes both sides.
- `EventReporter.Run` final flush uses
  `context.WithTimeout(context.Background(), 5*time.Second)` instead of
  `context.Background()`.

**Test**: `TestUpstreamHangTimesOut` — upstream accepts TCP but never responds;
assert proxy returns 504 within ~12s.

### 0.5 `randomSerial` must not degrade to predictable values

**Files**: `internal/proxyworker/builtin/mitm_ca.go:206`.

**Change**: if `rand.Int` fails, return an error from `LeafCertificate` rather
than falling back to `time.Now().UnixNano()`. Callers already handle errors.

**Test**: `TestRandomSerialFailurePropagates` — inject a failing reader.

### 0.6 Stop logging secret metadata to stderr

**Files**:

- `internal/proxyworker/secrets/secret_provider_vault.go:79` — remove the
  `mount=… path=… key=…` line, or route it through the Redactor with the path
  masked (e.g., `path=[redacted]`).
- `internal/controlplane/reconcile/vault_reconciler.go:92` — drop `secretPaths`
  from the audit record; replace with `secretCount`.

**Test**: `TestVaultProviderDoesNotLogSecretPath` — capture stderr, assert no
logged line contains the path.

### 0.7 Control-plane SPIFFE admin auth must consult RBAC

**Files**: `internal/controlplane/auth/request_auth.go` (was `server.go:790-792`).

**Change**: in `authorizedAdmin` for `AuthModeSPIFFE`, if `s.adminRBAC == nil`
and `s.insecure == false`, deny (return `adminAuthorization{}` with
`forbidden: true`). When `s.adminRBAC != nil`, require the peer SVID to map to
at least one role binding; deny if no bindings match.

**Test**: `TestSPIFFEAdminWithoutRBACBindingsDenies` — SPIFFE peer with no
bindings gets 403.

### 0.8 Enrollment fallback must fail closed without explicit config

**Files**: `internal/controlplane/workerapi/enrollment.go` (was
`server.go:826`).

**Change**: when `enrollmentAuthorizer == nil`, deny by default. Allow fallback
only when `--insecure` is set. Do not add a compatibility flag; this is
pre-release and the correct shape is explicit enrollment config or explicit
insecure mode.

**Test**: `TestEnrollmentWithoutAuthorizerDenies` — no `--auth-config`, no
`--insecure` → 403.

### 0.9 SPIRE reconcile label patch must be idempotent

**Files**: `internal/controlplane/reconcile/spire_reconciler.go:185-198`.

**Change**: use `"op": "replace"` for `/metadata/labels`, or use a test-and-add
pattern (`test` op on missing path, then `add`). Verify both first-run and
second-run succeed.

**Test**: `TestReconcileSPIREIsIdempotent` — run reconcile twice against a fake
K8s server, assert no error on second run.

### 0.10 Cluster-scoped resource names must include namespace

**Files**: `internal/controlplane/reconcile/spire_reconciler.go:127`,
`reconcile/vault_reconciler.go:155`.

**Change**: name template `airlock-<dnsLabel(ns)>-<dnsLabel(name)>` (with
collision-safe truncation to 253 chars). Rename existing resources in a one-shot
sweeper that lists `airlock-<name>`-pattern objects and recreates them under the
new name; safe because the software is pre-release.

**Test**: `TestReconcileDoesNotCollideAcrossNamespaces` — two workloads named
`demo` in `dev` and `prod` produce distinct resource names.

### 0.11 Admission webhook hardening

**Files**: `internal/controlplane/webhook/injection_webhook.go:154`.

**Change**:

- Wrap `r.Body` with `io.LimitReader(r.Body, 1<<20)`.
- Validate `review.Request.Kind.Kind == "Pod"` and
  `review.APIVersion == "admission.k8s.io/v1"`; return a 200 response with
  `Allowed: false` and a clear `Status.Message` otherwise.
- Verify the kube-apiserver client cert against a configurable CA
  (`--webhook-client-ca`) if set; reject unauthenticated callers.

**Tests**: `TestWebhookRejectsNonPodKind`, `TestWebhookRejectsOversizedBody`,
`TestWebhookRejectsUnauthenticatedCaller`.

### 0.12 Request size limits on K8s and OIDC fetches

**Files**: `internal/controlplane/store/kubernetes_source.go:269`,
`auth/oidc.go:71, 236`.

**Change**: wrap all `json.NewDecoder(resp.Body)` calls with
`io.LimitReader(resp.Body, maxFetchBytes)` where `maxFetchBytes` defaults to
4 MiB. OIDC discovery/JWKS use 1 MiB.

**Test**: `TestKubernetesClientRejectsOversizedList`,
`TestOIDCRejectsOversizedJWKS`.

---

## Sprint 1 — P1 Correctness / Runtime

### 1.1 Compiler purity

**Files**: `internal/policy/compiler.go:313-337` (`applyProviderDefaults`).

**Change**: deep-copy each `AirlockPolicy` before mutating. Implement
`func clonePolicy(p AirlockPolicy) AirlockPolicy` that copies `Egress` and
`Rewrites` slices. Add a test that calls `CompileWorkloadWithSecretProvider`
twice with different providers and asserts the input is unchanged after each
call.

### 1.2 Policy validation at load time

**Files**: `internal/controlplane/store/store.go:127-137` (`loadPolicies`),
`store/kubernetes_source.go:184-197`.

**Change**: call `policy.Validate` on every loaded `AirlockPolicy` at load time,
not only when referenced by a workload. Reject the load (file source) or log +
drop (K8s source) on validation failure. Add intra-policy duplicate-rule-name
detection in `Validate`. Normalize `Host` and `Scheme` to lowercase in
`Validate`. Document `Port == 0` semantics in a doc comment.

### 1.3 Graceful shutdown on both binaries

**Files**: `cmd/airlock-control-plane/main.go`, `cmd/airlock-proxy-worker/main.go`,
`internal/proxyworker/builtin/proxy.go` (`Serve`).

**Control plane**:

- Replace `context.Background()` with `ctx, stop := signal.NotifyContext(
  os.Interrupt, syscall.SIGTERM)`.
- Convert every `http.ListenAndServe` / `ListenAndServeTLS` to an explicit
  `http.Server{}` with `ReadHeaderTimeout: 10s`, `ReadTimeout: 30s`,
  `WriteTimeout: 30s`, `IdleTimeout: 120s`.
- Track all servers in a list; on `ctx.Done()`, call `server.Shutdown(
  shutdownCtx)` with a 10s deadline for each, in parallel via a
  `sync.WaitGroup`.
- The reconcile loop must accept `ctx` and exit on `ctx.Done()`; no leaked
  goroutines.

**Proxy worker**:

- `Serve(ctx, listener)` accepts a context. On `ctx.Done()`, close the listener
  and wait on a `sync.WaitGroup` tracking in-flight `HandleClient` goroutines.
- `HandleClient` goroutines exit promptly when the client connection closes or
  the context cancels.

**Test**: `TestControlPlaneGracefulShutdown` — start server, send a slow
request, send SIGTERM, assert the in-flight request completes and the process
exits within 12s. `TestWorkerGracefulShutdown` similar.

### 1.4 Unbounded map pruning

**Files**: `internal/controlplane/enrollment/enrollment.go`,
`internal/controlplane/server.go` (`Server.proxies`, `eventIngestBuckets`,
`eventSuppressed`).

**Changes**:

- `EnrollmentStore`: background sweeper goroutine (every 1 min) deletes tokens
  past `ExpiresAt`.
- `Server.proxies`: on every heartbeat-and-list pass, delete entries whose
  `LastSeen` is older than `5 * heartbeatInterval` (default 50s).
- `Server.eventIngestBuckets`: prune entries for proxies not present in
  `Server.proxies` after the proxy prune pass.
- `Server.eventSuppressed`: decay counters to zero on each prune pass; remove
  entries at zero.

**Test**: `TestEnrollmentSweeperDeletesExpiredTokens`,
`TestStaleProxiesArePruned`.

### 1.5 Rate limiting on worker and admin endpoints

**Files**: `internal/controlplane/workerapi/handlers.go`,
`adminapi/handlers.go`.

**Change**: introduce a small `ratelimit` sub-package with a token-bucket
limiter keyed by authenticated identity (or remote IP for unauthenticated
paths). Apply:

- `GET /v1/policies/`: 60 req/min per identity.
- `POST /v1/heartbeats`: 30 req/min per identity.
- `POST /v1/enrollments`: 10 req/min per issuer.
- `POST /v1/enrollments/redeem`: 30 req/min per remote IP.
- Admin GET endpoints: 120 req/min per identity.

Return 429 with `Retry-After` on exceed. Document that this is single-node;
distributed limiting is a future milestone.

**Test**: `TestPolicyFetchRateLimited`, `TestEnrollmentCreateRateLimited`.

### 1.6 HTTP server timeouts on all listeners

**Files**: `cmd/airlock-control-plane/main.go` (every listener),
`cmd/airlock-proxy-worker/main.go`.

**Change**: already covered in 2.3 for the control plane. For the worker builtin
proxy, set `http.Server{ReadHeaderTimeout: 10s, IdleTimeout: 120s}` on the
CONNECT listener. For ext_proc gRPC, set `grpc.MaxConnectionIdle`,
`MaxConnectionAge`, `KeepaliveParams` per gRPC best practices.

### 1.7 Env file secret provider sandboxing + caching

**Files**: `internal/proxyworker/secrets/secret_provider_env_file.go:20`.

**Change**:

- Add a configurable `--secret-file-root` (default empty = no restriction).
  When set, every `ref.File` must resolve under the root via `filepath.Rel`
  (reject if the result starts with `..`).
- Cache `(path, mtime) → value` with `os.Stat`-based invalidation. Re-read only
  when mtime changes.

**Test**: `TestEnvFileRespectsRoot`, `TestEnvFileCachesByMtime`.

### 1.8 Vault provider background refresh

**Files**: `internal/proxyworker/secrets/secret_provider_vault.go`.

**Change**: spawn a background goroutine that refreshes each cached secret at
`ttl/2`. On refresh failure, retain the old value until `ttl` expires, then
fail closed. Stop the goroutine via a `context.Context` tied to worker shutdown.

**Test**: `TestVaultProviderRefreshesBeforeExpiry`,
`TestVaultProviderFailsClosedAfterTTL`.

### 1.9 Admin TLS by default

**Files**: `cmd/airlock-control-plane/main.go` (admin listener),
`auth/auth_config.go`.

**Change**:

- Add `--admin-tls-cert` and `--admin-tls-key` flags.
- If neither is set, require `--insecure` to start the admin listener in plain
  HTTP.
- If both are set, serve via
  `http.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}`.
- Document in `--help` and the SPEC deployment section.

**Test**: `TestAdminListenerRequiresTLSWithoutInsecure`.

### 1.10 Case-insensitive Bearer scheme

**Files**: `internal/controlplane/auth/request_auth.go` (was `server.go:831`).

**Change**: parse the Authorization header case-insensitively per RFC 7235. Use
`strings.HasPrefix(strings.ToLower(value), "bearer ")` then strip the
original-length prefix.

**Test**: `TestBearerSchemeIsCaseInsensitive` (`bearer`, `BEARER`, `Bearer` all
accepted).

---

## Sprint 2 — Structural Prep

**Goal**: create clean package boundaries so subsequent library work is
localized. Start with same-package file splits and leaf package extraction; do
not force handlers into sub-packages until the required public interfaces are
obvious from the P0/P1 work.

### 2.1 Split `internal/controlplane` into sub-packages

Target layout:

```
internal/controlplane/
  workerapi/      # /v1/policies, /v1/heartbeats, /v1/events, /v1/enrollments (worker listener)
  adminapi/       # /v1/admin/* (admin listener)
  enrollment/     # EnrollmentStore, EnrollmentAuthorizer, token mint/redeem
  webhook/        # admission webhook handler
  reconcile/      # spire_reconciler, vault_reconciler
  store/          # PolicyStore, file loading
  auth/           # request_auth, oidc, rbac, auth_config
  server.go       # shared Server struct, lifecycle, listener wiring
```

Move files in small reviewable batches. Prefer same-package file splits first;
extract sub-packages only when the boundary is clear:

- `server.go` → split into `server.go` (lifecycle) + `workerapi/handlers.go` +
  `adminapi/handlers.go` + `adminapi/summary.go` + `server/audit.go`
- `store.go` → `store/store.go`
- `enrollment.go` → `enrollment/enrollment.go`
- `events.go` → `workerapi/events.go`
- `request_auth.go`, `oidc.go`, `rbac.go`, `auth_config.go` → `auth/`
- `kubernetes_source.go` → `store/kubernetes_source.go` (will move again in
  Sprint 4)
- `spire_reconciler.go`, `vault_reconciler.go` → `reconcile/`
- `injection_webhook.go` → `webhook/`

Export symbols as needed to cross package boundaries. Prefer small, focused
exported types over re-exporting internals.

### 2.2 Split `internal/proxyworker` into sub-packages

Target layout:

```
internal/proxyworker/
  builtin/        # http:builtin proxy (proxy.go, mitm_ca.go)
  extproc/        # http:envoy ext_proc (ext_proc.go, ext_proc_grpc.go)
  sds/            # SDS server (envoy_services.go)
  secrets/        # secret_provider*.go, vault_client.go
  policy/         # policy_provider.go
  telemetry/      # event_log.go, event_reporter.go, heartbeat.go
  types.go        # shared ValidateCompiledPolicy, ValidationError
  worker.go       # ProxyServer lifecycle (top-level)
```

### 2.3 Split monolithic entrypoints

- `cmd/airlock-control-plane/main.go:run()` (344 LOC) → `parseFlags`,
  `buildAuth`, `buildStore`, `startListeners`, `runReconcile`, `waitForShutdown`.
- `cmd/airlock-proxy-worker/main.go:run()` (~240 LOC) → `parseFlags`,
  `loadPolicy`, `buildSecrets`, `buildMITMCA`, `startReporters`,
  `startListener`, `waitForShutdown`.

### 2.4 Lint baseline

Add `.golangci.yml` (or `revive` config) enabling at minimum: `errcheck`,
`govet`, `ineffassign`, `staticcheck`, `unused`, `error-strings`, `exported`,
`package-comments`, `context-as-argument`, `context-keys-type`. Wire
`golangci-lint run` + `go test -race ./...` into the Makefile `check` target.
Fix only the failures that block the build (e.g., unused vars); defer stylistic
fixes to Sprint 5.

**Exit criteria**: `go build ./...`, `go test -race ./...`, and
`golangci-lint run` all pass after each extraction. No intentional behavior
change.

---

## Sprint 3 — Builtin Proxy Swap + Worker Live Reload

This sprint replaces the builtin proxy implementation and adds live policy
reload. Land `goproxy` in this refactor with the hardening suite and new
CONNECT keep-alive tests passing before deleting the old parser/tunnel code.

### 3.1 Worker live reload

**Files**: `internal/proxyworker/worker.go`, `builtin/proxy.go`,
`extproc/ext_proc_grpc.go`, `policy/policy_provider.go`,
`cmd/airlock-proxy-worker/main.go`.

**Change**:

- `ProxyServer.policy` and `ExtProcGRPCServer.policy` become
  `atomic.Pointer[policy.CompiledPolicy]`.
- `HandleClient` / `EvaluateExtProcHeaders` load the pointer at the top of each
  request (`s.policy.Load()`).
- `PolicyProvider` gains a `Watch(ctx) <-chan policy.CompiledPolicy` method. The
  control-plane provider polls `GET /v1/policies/` every
  `--policy-poll-interval` (default 30s) with `If-None-Match` / ETag support;
  the control plane returns 304 when unchanged.
- `cmd/airlock-proxy-worker/main.go` spawns a goroutine that calls `Watch(ctx)`
  and `s.policy.Store(newPolicy)` on every update.
- `EventReporter.sourcePolicyByRule` reads the current pointer per event rather
  than caching at construction.

**Tests**: `TestPolicyReloadDeniesPreviouslyAllowedDestination` (live swap,
mid-connection new requests denied),
`TestPolicyReloadAllowsPreviouslyDeniedDestination`,
`TestPolicyPollHandlesNotModified`.

### 3.2 Adopt `elazarl/goproxy` for the builtin proxy

**Files**: replace `internal/proxyworker/builtin/proxy.go` (~534 LOC) and
`builtin/mitm_ca.go` MITM plumbing with a goproxy-based implementation.

**Change**:

- `go get github.com/elazarl/goproxy`.
- Implement `ProxyServer.Serve(ctx, listener)` using
  `goproxy.NewProxyHttpServer()`.
- Register `OnRequest().HandleConnect(...)` that consults `s.policy.Load()` and
  `FindEgressRule`; sets the MITM CA via `goproxy.GoproxyCa` from
  `LoadCertificateAuthority`.
- Register `OnRequest(...)` that runs `ApplyRewrites` and rejects CRLF values
  (Sprint 0.1).
- Register `OnResponse(...)` that enforces `maxResponseBytes` via a
  `LimitReader` wrapper (Sprint 0.3).
- Delete the hand-rolled parser (`readHTTPRequestBytes`, `parseRequestHead`,
  `OriginFormBytes`) and `tunnelConnect` (goproxy handles CONNECT tunneling).
- Keep `mitm_ca.go` for CA load/mint, but the leaf-serving path is delegated to
  goproxy.
- Update `worker_test.go` and `hardening_test.go` to the new constructor; tests
  should pass unchanged in behavior.

**Exit criteria**: all existing proxy tests pass against the goproxy
implementation. New test
`TestHTTPSConnectHandlesMultipleRequestsPerTunnel` (keep-alive over MITM).

---

## Sprint 4 — Library and Observability Swaps

Land each library swap as an isolated PR with its own test pass. These are
valuable, but they should not be bundled with the data-path replacement.

### 4.1 Migrate to `sigs.k8s.io/controller-runtime`

**Files**: `internal/controlplane/store/kubernetes_source.go`,
`reconcile/spire_reconciler.go`, `reconcile/vault_reconciler.go`,
`webhook/injection_webhook.go`, `cmd/airlock-control-plane/main.go`.

**Change**:

- `go get sigs.k8s.io/controller-runtime@v0.18+`.
- Generate typed CRD clients for `AirlockPolicy`, `AirlockWorkload`,
  `SecretProviderConfig` via `controller-gen` (add
  `//+kubebuilder:object:root=true` markers to `api/v1alpha1/types.go`).
- Replace `LoadPolicyStoreFromKubernetes` with a `Manager`-backed informer
  cache; the store reads from the cache (no 10s poll).
- Replace `PatchAirlockWorkloadStatus` with
  `client.Status().Patch(ctx, obj, client.MergeFrom(base))` using
  `resourceVersion` preconditions.
- Reconcilers become `Reconciler` implementations; SPIRE/Vault reconcile runs on
  workload create/update/delete events (not a global tick).
- Admission webhook becomes `admission.Handler` registered with the manager; the
  manager handles TLS and request validation.
- Add leader election (`Manager.Options.LeaderElection`) so multi-replica
  control planes are safe.

**Tests**: `TestReconcilerReconcilesOnCreate`, `TestReconcilerRetriesOnConflict`,
`TestWebhookHandlerRejectsNonPodKind`, `TestLeaderElection`.

### 4.2 Adopt `hashicorp/vault/api` for both binaries

**Files**: `internal/proxyworker/secrets/vault_client.go`,
`internal/proxyworker/secrets/secret_provider_vault.go`,
`internal/controlplane/reconcile/vault_reconciler.go`.

**Change**:

- `go get github.com/hashicorp/vault/api`.
- Worker: `NewVaultSecretProvider` builds a `vault.Client` with
  `vault.Config{Address, HttpClient: &http.Client{Timeout: 10s}}`. JWT login via
  `client.Auth().JWT().Login(...)`. KV-v2 reads via
  `client.KVv2(mount).Get(ctx, path)`. The library handles path escaping
  (closes the traversal class from 1.2 at the library level). Keep the
  background refresh from 2.8; the library exposes `Secret.LeaseDuration` for
  TTL.
- Control plane: `vault_reconciler.go` uses
  `client.Sys().CreateOrUpdatePolicy(name, rules)` and
  `client.Auth().JWT().CreateRole(ctx, name, role)`. Configurable TLS via
  `vault.Config{TLSConfig: vault.TLSConfig{CACert: ...}}`.
- Delete `vault_client.go` and the raw HTTP code in `vault_reconciler.go`.

**Tests**: existing `TestVaultSecretProviderCacheTTL`,
`TestVaultKV2Non200FailsClosed` rewritten against a `httptest.Server` mock of
Vault's API.

### 4.3 Adopt `coreos/go-oidc/v3` and `golang-jwt/jwt/v5`

**Files**: `internal/controlplane/auth/oidc.go` (280 LOC),
`auth/request_auth.go`.

**Change**:

- `go get github.com/coreos/go-oidc/v3/oidc` and
  `github.com/golang-jwt/jwt/v5`.
- Replace hand-rolled discovery + JWKS fetch + claim validation with
  `oidc.NewProvider(ctx, issuer)` and
  `provider.Verifier(&oidc.Config{ClientID: aud}).Verify(ctx, rawToken)`.
- Drop `oidc.go` entirely; the `OIDCRequestAuthenticator` becomes ~30 lines.

**Tests**: `TestOIDCRefreshesJWKSOnKeyRotation` (mock provider rotates keys,
assert second request succeeds), `TestOIDCRejectsWrongAudience`.

### 4.4 Adopt `go-chi/chi/v5` for HTTP routing and middleware

**Files**: `internal/controlplane/server.go`, `workerapi/handlers.go`,
`adminapi/handlers.go`, `webhook/injection_webhook.go`.

**Change**:

- `go get github.com/go-chi/chi/v5`.
- Replace `http.ServeMux` with `chi.NewRouter()` per surface. Middleware chain:
  `middleware.RequestID`, `middleware.RealIP`, `middleware.Recoverer`,
  `middleware.Timeout(30*time.Second)`, a small access-log middleware
  (slog-based, see 3.7), and a body-limit middleware (`http.MaxBytesReader`).
- Route groups: `r.Route("/v1/policies", ...)` etc. Per-route
  `Use(authMiddleware, ratelimitMiddleware)`.

### 4.5 Adopt `log/slog`

**Files**: all files currently using `fmt.Fprintf(os.Stderr, ...)` or
`log.Printf`.

**Change**:

- Define `var log = slog.New(slog.NewJSONHandler(os.Stderr, nil))` in each
  binary's `main.go`; allow handler selection via `--log-format=json|text`.
  Default to JSON (no BC concern).
- Replace every `fmt.Fprintf(os.Stderr, "k=v ...")` with
  `log.InfoContext(ctx, "message", slog.String("k", v))`.
- The `Redactor` (worker) wraps the slog handler and scrubs known secret values
  from string attrs.
- Audit log (control plane) becomes a dedicated `slog.Handler` writing to a
  separate file/stderr with its own format; no more mixing JSON audit lines
  with text `log.Printf` lines.
- `event_log.go`'s `containsAll(message, "allowed", "request")` decision
  classification is replaced by an explicit `DecisionKind` enum passed to
  `Record` (see Sprint 5.5).

### 4.6 Adopt `prometheus/client_golang`

**Files**: new `internal/proxyworker/telemetry/metrics.go`,
`internal/controlplane/telemetry/metrics.go`.

**Change**:

- Worker: counters
  `airlock_proxy_decisions_total{workload, kind=allow|deny|error}`, histogram
  `airlock_proxy_request_duration_seconds`, gauge
  `airlock_proxy_active_connections`, counter
  `airlock_secret_resolve_total{provider, result}`. Expose `/metrics` only when
  `--metrics-listen` is set; local examples may use `127.0.0.1:9090`, but
  embedded/sandbox deployments should not open a listener by default.
- Control plane: counters `airlock_cp_requests_total{surface, code}`,
  `airlock_cp_auth_failures_total{mode}`, `airlock_cp_events_ingested_total`,
  `airlock_cp_events_dropped_total{reason}`, gauge
  `airlock_cp_active_proxies`, histogram
  `airlock_cp_reconcile_duration_seconds{kind}`.

### 4.7 Adopt `go.opentelemetry.io/otel`

**Files**: new `internal/otel/otel.go`, integration in both binaries.

**Change**:

- `go get go.opentelemetry.io/otel
  go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp
  go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc`.
- Worker: span per `HandleClient` / `EvaluateExtProcHeaders`; attributes
  `egress.host`, `egress.port`, `decision`, `secret.provider` (no secret
  values).
- Control plane: `otelhttp.NewHandler` wraps each surface's router; spans on
  `GetPolicy`, `RedeemEnrollment`, `IngestEvents`, `ReconcileSPIRE`,
  `ReconcileVault`.
- Exporter configurable via `--otel-exporter-otlp-endpoint`.

### 4.8 Replace `fmt.Sscanf` int parsing and adopt `envconfig`

**Files**: `cmd/airlock-control-plane/main.go:384-496` (env helpers),
`cmd/airlock-proxy-worker/main.go`.

**Change**:

- `go get github.com/kelseyhightower/envconfig`.
- Define a `Config` struct per binary with `envconfig:"FOO"` tags. Replace
  `envIntOrDefault`, `envFloatOrDefault`, `envStringOrDefault` with
  `envconfig.Process`.
- Delete the hand-rolled helpers.

### 4.9 Adopt `testify`

**Files**: all `*_test.go`.

**Change**: `go get github.com/stretchr/testify/assert
github.com/stretchr/testify/require`. Migrate assertions incrementally,
prioritizing the struct-comparison tests in `server_test.go`
(`summarizeWorkload`) and `compiler_test.go`. Keep `t.Fatalf` only where
`require` is genuinely clearer.

---

## Sprint 5 — Hygiene

Lower-risk work that can land incrementally.

### 5.1 Doc comments on all exported symbols

Run `golangci-lint run --enable exported,package-comments`. Add
`// Symbol does …` to every exported symbol and `// Package foo …` to every
package. Prioritize `api/v1alpha1` (public wire contract) and the new
sub-package boundaries.

### 5.2 Error string style

Enable `revive` rule `error-strings`. Fix violations: lowercase first letter,
no terminal punctuation. Examples to fix: `"Vault JWT login failed"` →
`"vault JWT login failed"`. Use judgment for proper nouns (`Vault`, `SPIFFE`,
`MITM`, `OIDC`) — keep them capitalized, but lowercase the first word of the
sentence.

### 5.3 Deduplicate

- `dnsLabelPart`: exists in `reconcile/vault_reconciler.go:199` and
  `policy/compiler.go:397`. Move to a shared `internal/dns/dns.go` (or
  `internal/names/`).
- `setHeader` / `deleteHeader` (`builtin/proxy.go:448, 458`): share a
  `filterHeaders` helper.
- `splitHostPort` / `parseHTTPURL`: consolidate into
  `internal/netutil/hostport.go`. Add IPv6 literal support.
- The four "denied … request policy=… policy_version=…" log builders: one
  helper `formatDecisionLog(decision, rule, policy)`.
- Hand-rolled `httpGet` / `readHTTPResponse` in `policy_provider.go`: replaced
  by `http.Client` + `http.ReadResponse`; will be removed entirely when goproxy
  lands if the policy provider is refactored, otherwise consolidate.

### 5.4 Replace `latestTimePtr` with Go 1.21 generics

`server.go:708-717` → `max` with pointer dereference or a generic
`ptrMax[T cmp.Ordered]` helper.

### 5.5 Structured decision classification

**Files**: `internal/proxyworker/telemetry/event_log.go`,
`telemetry/event_reporter.go`.

**Change**: introduce `type DecisionKind string` constants (`Allow`, `Deny`,
`ProxyError`, `SecretError`). `EventLog.Record` accepts a `DecisionKind`
alongside the message. `observeDecisionLocked` switches on the enum instead of
`containsAll` string matching. `EventReporter` reads the enum directly; delete
`keyValueFields` string parsing (`event_reporter.go:397`).

### 5.6 Stop swallowing encode errors

**Files**: `server.go:960, 998`, `store/kubernetes_source.go:318`,
`workerapi/events.go:396`.

**Change**: log encode failures via `slog.ErrorContext`. For audit records,
fall back to a plain-text `slog.Error` line with the audit fields if JSON
encoding fails.

### 5.7 SDS version stability

**Files**: `internal/proxyworker/sds/envoy_services.go:92`.

**Change**: compute `VersionInfo` as
`hex.EncodeToString(sha256(cert.Bytes))` rather than `time.Now()`. Only changes
when the leaf cert actually changes.

### 5.8 Receiver consistency

Document the stateless-vs-stateful receiver convention in
`internal/proxyworker/CONVENTIONS.md` (or in `docs/contributing.md`). Unify
`EnvFileSecretProvider.Resolve` to pointer receiver for consistency with
`VaultSecretProvider` if it ends up with state (cache from 2.7).

### 5.9 Test gap closure

Add tests for:

- `LoadCertificateAuthority` error paths (bad PEM, non-CA cert, bad key).
- `tunnelConnect` half-close behavior (will move to goproxy's tests in 3.2; add
  an integration test anyway).
- `ServeLimit` cap enforcement.
- IPv6 host parsing.
- OIDC JWKS refresh on key rotation (covered in 4.3).
- `ReplaceStore` vs concurrent reads under `-race`.
- Admission webhook non-Pod kind (covered in 0.11).
- Partial reconcile failure: one workload's SPIRE create succeeds, the next
  fails — assert the first is not rolled back and the error is surfaced; the
  next reconcile retries the failed one.
- Live reload: `TestPolicyReloadDeniesPreviouslyAllowedDestination` (from 3.1).
- Golden-file fixtures for `CompileWorkloadWithSecretProvider` outputs.

### 5.10 Golden-file fixtures

Move inline test inputs in `compiler_test.go` to `fixtures/compiler/*.yaml` and
compare outputs against `fixtures/compiler/*.golden.json`. Add `go test -update`
flag to regenerate.

---

## Cross-Cutting Conventions

These apply across all sprints:

- **Context first**: every function that does I/O takes `ctx context.Context`
  as its first parameter (golangci-lint `context-as-argument`).
- **Errors wrap**: every `fmt.Errorf` that wraps uses `%w`; never `%s` for an
  underlying error.
- **No `panic` in request paths**: only at startup for unrecoverable
  misconfiguration.
- **Fail closed**: ambiguous state (missing policy, missing secret, unknown auth
  mode) denies. Add a regression test for each fail-closed path.
- **Secret redaction**: any log/metric/trace attribute derived from user or
  secret data passes through the `Redactor`. No secret path or value in any
  telemetry.
- **One concern per commit**: each P0/P1 item lands as its own commit with its
  own test. Library swaps (Sprint 4) land as one PR per library.
- **Race detector**: `go test -race ./...` must pass on every commit.
- **No backwards compatibility**: old flags, log formats, package paths, and
  HTTP shapes may be removed freely. Update callers and tests in the same
  commit.

---

## Out of Scope (Explicit Non-Goals)

- Database-backed mutable policy store (SPEC open question).
- Distributed rate limiting across control-plane replicas.
- Git HTTPS proxy mode (`git:builtin`) — future milestone.
- OIDC token exchange providers — future milestone.
- ClickHouse/Loki/OTEL backend integration in the WebUI — future milestone.
- WebUI changes beyond consuming the new `/metrics` and audit format.
- Helm chart (future milestone per SPEC).

---

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| `goproxy` adoption changes MITM behavior in subtle ways | Run the existing `hardening_test.go` suite against goproxy first; add keep-alive and multi-request-per-CONNECT tests before deleting the old code. |
| `controller-runtime` migration is large | Land in three PRs: (a) typed CRD clients + controller-gen, (b) informers replacing poll, (c) reconcilers + webhook. Each PR removes the old path; no flag-gated coexistence. |
| Live reload introduces TOCTOU (policy changes mid-request) | The pointer load is at request start; a request uses one policy snapshot for its entire lifetime. Documented. |
| `slog` migration breaks log consumers | No BC concern — pre-release. Default to JSON from day one. |
| Sub-package split causes import churn that obscures review | Sprint 2 starts with same-package file splits and extracts leaf packages in small batches. Reviewers diff with `--find-renames` where files move. |

---

## Definition of Done

- All P0 (Sprint 0) and P1 (Sprint 1) items merged with regression tests.
- `goproxy`, `controller-runtime`, `vault/api`, `go-oidc`, `chi`, `slog`,
  `prometheus`, `otel`, `testify`, `envconfig` all adopted (Sprints 3 and 4).
- `golangci-lint run` and `go test -race ./...` pass on `main`.
- No secret path or value in any log line, metric, or trace (verified by a
  `TestNoSecretsInLogs` integration test that captures
  stderr/metrics/traces).
- `SPEC.md` updated to reflect: live reload, admin TLS default, sub-package
  layout, library choices.
