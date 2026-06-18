# Control Plane With API-Key Enrollment

This example uses a control plane, API-key dispatcher enrollment, and the
builtin HTTP proxy.

Flow:

1. `enrollment-token` calls `POST /v1/enrollments` with a dispatcher API key.
2. `proxy-worker` redeems that one-time token with
   `POST /v1/enrollments/redeem` and receives the compiled policy.
3. `curl-workload` makes one allowed request through the proxy and confirms the
   proxy injected `X-Airlock-Demo-Secret` from a file only mounted into the proxy.
4. `curl-workload` makes one denied request and expects it to fail closed.

Run:

```sh
docker compose -f examples/compose/control-plane-enrollment/compose.yaml up --build --abort-on-container-exit --exit-code-from curl-workload
```

Admin smoke:

```sh
curl -fsS -H 'Authorization: Bearer compose-console-token' \
  http://127.0.0.1:18211/v1/admin/workloads
```

Cleanup:

```sh
docker compose -f examples/compose/control-plane-enrollment/compose.yaml down -v
```
