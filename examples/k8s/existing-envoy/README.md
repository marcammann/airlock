# Existing Envoy Kubernetes Example

This example deploys a demo app that already owns its Envoy sidecar. The
Airlock webhook injects only the proxy worker, and the existing Envoy routes
egress decisions through that worker.

Apply it after the Airlock baseline demo is installed:

```sh
kubectl apply -k examples/k8s/existing-envoy
```

For a scripted smoke, run `scripts/smoke/k8s-egress-smoke.sh` with the
`SMOKE_NAME`, `WORKLOAD_DEPLOYMENT`, `WORKLOAD_LABEL`, `WORKLOAD_MANIFEST`, and
`ALLOW_SOURCE_ENVOY=true` environment variables set for this manifest.
