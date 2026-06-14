# Docker Compose Proxy Observability Demo

This demo keeps the Airlock proxy worker in its own long-running container so
you can watch heartbeats and decision counters without the app container exiting.

Topology:

```text
control-plane  -> worker API :8080, admin API :8081
proxy-worker   -> builtin HTTP proxy on :18080, heartbeat every 2s
proxy-worker-denied -> second builtin HTTP proxy on :18080, same policy
web-ui         -> Airlock admin console at http://127.0.0.1:13000
client         -> curl container requesting http://example.com every 10s
client-denied  -> curl container requesting http://iana.org every 10s
```

The proxy worker controls `--heartbeat-interval`; the control plane controls
`--heartbeat-stale-threshold`. This demo uses a 2 second interval and the
compose stale threshold of 3, so the proxy becomes stale after about 6 seconds
without a heartbeat.

Denied and error events are aggregated by each proxy worker and reported to the
control plane through `/v1/events`. The Web UI reads the bounded in-memory event
log through `/v1/admin/events`; allowed request history remains a metrics or
external telemetry concern.

Run:

```sh
make compose-proxy-observability-up
```

Open the admin UI:

```text
http://127.0.0.1:13000/proxies
```

The optional WebUI service uses `AIRLOCK_WEB_AUTH_MODE=dev` in this local demo.
Because the demo is plain HTTP, it also sets `AIRLOCK_WEB_COOKIE_SECURE=false`.
Open `/login` first if the console asks you to sign in.

The `client` service automatically generates an allowed request every 10
seconds. The `client-denied` service automatically generates a denied request
against a second proxy worker using the same policy, so the proxy list should
show two active proxies with different decision counters.

You can also generate an allowed request manually:

```sh
docker compose -f examples/compose/proxy-observability/compose.yaml exec client \
  curl -v http://example.com/
```

Generate a denied request:

```sh
docker compose -f examples/compose/proxy-observability/compose.yaml exec client-denied \
  curl -v http://iana.org/
```

Watch proxy and client logs:

```sh
make compose-proxy-observability-logs
```

Clean up:

```sh
make compose-proxy-observability-down
```

The policy intentionally allows only `http://example.com:80`. The allowed client
uses `HTTP_PROXY=http://proxy-worker:18080`; the denied client uses
`HTTP_PROXY=http://proxy-worker-denied:18080`. Both workers use the same
workload identity and policy, while the control plane distinguishes them by
their container IP-derived proxy IDs.
