# Injected Sidecar Kubernetes Example

This example deploys a demo app annotated for the Airlock mutating webhook. The
webhook injects the proxy worker and managed Envoy sidecars.

Apply it after the Airlock baseline demo is installed:

```sh
kubectl apply -k examples/k8s/injected-sidecar
```

The Makefile target `injected-sidecar-smoke` applies this manifest during its
smoke test.

