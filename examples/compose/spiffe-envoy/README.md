# Control Plane With SPIFFE And Envoy

This example runs a local SPIRE server/agent, a SPIFFE-authenticated Airlock
control plane, Envoy, and a proxy-worker in `http:envoy` mode.

Flow:

1. SPIRE starts with a join-token agent.
2. The bootstrap service registers SVIDs for `/airlock-control-plane` and
   `/airlock-proxy-worker`.
3. The proxy-worker fetches policy from the control plane over SPIFFE mTLS.
4. Envoy calls the proxy-worker ext_proc API for each request.
5. `curl-workload` verifies one allowed request with a proxy-injected file
   secret and one denied request.

Run:

```sh
docker compose -f examples/compose/spiffe-envoy/compose.yaml up --build --abort-on-container-exit --exit-code-from curl-workload
```

Admin smoke:

```sh
curl -fsS http://127.0.0.1:18311/v1/admin/workloads
```

Cleanup:

```sh
docker compose -f examples/compose/spiffe-envoy/compose.yaml down -v
```
