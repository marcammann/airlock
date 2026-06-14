# Basic Egress Kubernetes Example

This example deploys a demo workload, a standalone Airlock proxy worker, Envoy,
an echo upstream, and the Airlock workload/policy resources that allow egress to
that upstream.

Apply it after installing Airlock and loading the proxy worker image:

```sh
kubectl apply -k examples/k8s/basic-egress
```

The Makefile target `deploy-demo` applies this example and waits for the core
deployments to roll out.

