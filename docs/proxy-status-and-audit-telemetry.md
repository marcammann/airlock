# Proxy Status and Audit Telemetry

## Status Source

The control plane owns current proxy inventory. Proxies report a heartbeat on a
fixed interval, and the control plane marks a proxy active while that heartbeat
is fresh.

Initial endpoint:

```text
GET /v1/admin/proxies
```

Worker endpoint:

```text
POST /v1/proxies/heartbeat
```

Suggested heartbeat fields:

- proxy ID
- proxy type: `http:builtin`, `http:envoy`, `git:builtin`
- workload SPIFFE ID
- heartbeat interval, as a duration string such as `10s`
- workload name, effective policy version, and effective policy hash
- process start time
- last successful policy fetch time
- last failed policy fetch time and redacted error class
- pod name, namespace, node name, and service account when running in Kubernetes
- worker binary version and build info

The proxy worker owns `--heartbeat-interval`. The control plane owns
`--heartbeat-stale-threshold`, which is the number of missed heartbeat intervals
allowed before the proxy is marked stale.

```text
stale_after = reported_heartbeat_interval * heartbeat_stale_threshold
```

Current defaults are `--heartbeat-interval=10s` on the worker and
`--heartbeat-stale-threshold=9` on the control plane, so a proxy becomes stale
after roughly 90 seconds without a heartbeat.

## Audit Telemetry

Airlock separates operational console events from full request telemetry.
Allowed request history belongs in OTEL, Prometheus counters, or another
operator-owned telemetry backend. The control plane only accepts recent
Airlock-specific denied/error events so the console can show useful alerts
without becoming a log database.

The proxy reports aggregated events to:

```text
POST /v1/events
```

The control plane stores those events in a bounded in-memory event log by
default. It is intentionally not durable audit storage. Production deployments
should still export full telemetry to their existing observability stack, and
can later wire the Airlock Console to ClickHouse, Loki, or another backend for
long-term history.

Supported event types:

- `egress.denied`
- `proxy.error`
- `policy.fetch_failed`
- `secret.resolve_failed`
- `control_plane.auth_failed`
- `event.suppressed`

Suggested OTEL attributes for external telemetry:

- `event.name`: `airlock.egress.decision`
- `airlock.decision`: `allowed`, `denied`, or `proxy_error`
- `airlock.reason`: `policy_match`, `no_matching_egress`, `secret_unavailable`
- `airlock.proxy.id`
- `airlock.proxy.type`
- `airlock.workload.name`
- `airlock.workload.namespace`
- `airlock.workload.spiffe_id`
- `airlock.effective_policy.version`
- `airlock.effective_policy.hash`
- `airlock.source_policy.name`
- `airlock.source_policy.namespace`
- `airlock.egress.rule`
- `airlock.destination.scheme`
- `airlock.destination.host`
- `airlock.destination.port`
- `http.request.method`
- `url.path`, only when safe and after query redaction
- `spiffe.id`
- `k8s.namespace.name`
- `k8s.pod.name`

`event.name=airlock.egress.decision` is the primary discriminator that separates
Airlock decision records from other OTEL logs. The Airlock-specific
attributes then support filtering within that stream:

- `airlock.proxy.id` for a specific proxy instance
- `airlock.decision` for `allowed`, `denied`, or `proxy_error`
- `airlock.workload.name`, `airlock.workload.namespace`, and
  `airlock.effective_policy.version` for effective policy context
- `airlock.source_policy.name` and `airlock.source_policy.namespace` for the
  reusable policy that supplied a matched allow rule
- `airlock.egress.rule` and destination attributes for route context

Do not emit request headers, rewritten values, secret refs, token values, or full
URLs with sensitive query strings. The existing worker redaction tests should be
extended to cover structured OTEL payloads before enabling export by default.

Event-reporting controls on the proxy:

```text
--event-report=control-plane|disabled
--event-endpoint=https://control-plane.example/v1/events
--event-report-rate=1
--event-report-burst=20
--event-report-pending-limit=256
--event-report-flush-interval=1s
```

Event-log controls on the control plane:

```text
--event-log=memory|disabled
--event-log-limit=1000
--event-log-ttl=24h
--event-ingest-rate=100
--event-ingest-burst=500
--event-ingest-rate-per-proxy=2
--event-ingest-burst-per-proxy=50
```

The proxy aggregates repeated events before sending them. If its local pending
set fills, it emits an `event.suppressed` summary. The control plane also applies
global and per-proxy token buckets and reports suppressed counts through the
admin API.

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

The WebUI reads current proxy status from the control plane. For recent
denied/error history, the UI queries a stable Airlock admin API backed by the
current event log:

```text
GET /v1/admin/events?proxy_id=...&type=...&severity=...&limit=...&cursor=...
```

The event endpoint uses cursor pagination. `limit` defaults to 50 and is capped
at 100. `nextCursor` is opaque and should be passed back unchanged as `cursor`
to fetch older records.

The memory backend is for recent console state. A future durable backend can
query ClickHouse, Loki, Elasticsearch, Honeycomb, or another OTEL destination
without changing the WebUI route shape.
