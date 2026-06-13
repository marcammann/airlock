# Proxy Status and Audit Telemetry

## Status Source

The control plane should own current proxy inventory. Proxies report a heartbeat
or lease on a fixed interval, and the control plane marks a proxy active while
that lease is fresh.

Initial endpoint:

```text
GET /v1/admin/proxies
```

Future worker endpoint:

```text
POST /v1/proxies/heartbeat
```

Suggested heartbeat fields:

- proxy ID
- proxy type: `http:builtin`, `http:envoy`, `git:builtin`
- workload SPIFFE ID
- policy name, version, and hash
- process start time
- last successful policy fetch time
- last failed policy fetch time and redacted error class
- pod name, namespace, node name, and service account when running in Kubernetes
- worker binary version and build info

An active proxy is one whose last heartbeat is within the configured TTL. A good
default is a 30 second heartbeat and a 90 second active TTL.

## Audit Telemetry

OTEL is a good fit for request decision audit trails: allowed, denied, and
dependency-failed egress decisions emitted by each proxy. This should complement
the status store rather than replace it.

Each request decision should emit an OTEL log record, and optionally a span event
when a request span is active.

Suggested log attributes:

- `event.name`: `airlock.egress.decision`
- `airlock.decision`: `allowed`, `denied`, or `dependency_failed`
- `airlock.reason`: `policy_match`, `no_matching_egress`, `secret_unavailable`
- `airlock.proxy.id`
- `airlock.proxy.type`
- `airlock.policy.name`
- `airlock.policy.version`
- `airlock.policy.hash`
- `airlock.egress.rule`
- `airlock.destination.scheme`
- `airlock.destination.host`
- `airlock.destination.port`
- `http.request.method`
- `url.path`, only when safe and after query redaction
- `spiffe.id`
- `k8s.namespace.name`
- `k8s.pod.name`

Do not emit request headers, rewritten values, secret refs, token values, or full
URLs with sensitive query strings. The existing worker redaction tests should be
extended to cover structured OTEL payloads before enabling export by default.

## Metrics

Suggested proxy metrics:

- `airlock_proxy_heartbeat_total`
- `airlock_proxy_active`
- `airlock_policy_fetch_total`, labeled by result
- `airlock_policy_fetch_age_seconds`
- `airlock_egress_decision_total`, labeled by decision, policy, rule, and host
- `airlock_secret_resolution_total`, labeled by provider and result

Keep labels bounded. Policy names, rule names, result, provider, and destination
host are acceptable. Full paths, query strings, user IDs, token hashes, and
request IDs are not acceptable metric labels.

## Query Model

The WebUI should read current proxy status from the control plane. For request
audit history, the UI can link to an OTEL-backed backend later:

```text
GET /v1/admin/proxies/{id}/decisions
GET /v1/admin/audit/egress-decisions
```

That backend can query Loki, Elasticsearch, ClickHouse, Honeycomb, or another
OTEL destination. The Airlock API should stay stable even if the telemetry
backend changes.
