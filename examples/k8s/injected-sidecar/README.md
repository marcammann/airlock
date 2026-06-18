# Injected Sidecar Kubernetes Example

This example deploys a demo app annotated for the Airlock mutating webhook. The
webhook injects the proxy worker and managed Envoy sidecars.

Apply it after the Airlock baseline demo is installed:

```sh
kubectl apply -k examples/k8s/injected-sidecar
```

For a scripted smoke, run `scripts/smoke/k8s-egress-smoke.sh` with the
`SMOKE_NAME`, `WORKLOAD_DEPLOYMENT`, `WORKLOAD_LABEL`, and `WORKLOAD_MANIFEST`
environment variables set for this manifest.
