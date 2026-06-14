# Existing Envoy Kubernetes Example

This example deploys a demo app that already owns its Envoy sidecar. The
Airlock webhook injects only the proxy worker, and the existing Envoy routes
egress decisions through that worker.

Apply it after the Airlock baseline demo is installed:

```sh
kubectl apply -k examples/k8s/existing-envoy
```

The Makefile target `existing-envoy-smoke` applies this manifest during its
smoke test.

