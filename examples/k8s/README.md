# Kubernetes Examples

Runnable Kubernetes scenarios live here. Keep reusable Airlock installation
assets in `deploy/k8s`; use this directory for demo workloads, policies,
workloads, upstreams, and data-path variants.

- `basic-egress`: standalone proxy worker, Envoy, echo upstream, and the
  Airlock workload/policy resources used by the kind demo.
- `injected-sidecar`: app annotated for webhook-managed Envoy and proxy worker
  injection.
- `existing-envoy`: app with its own Envoy sidecar where Airlock injects only
  the proxy worker.

