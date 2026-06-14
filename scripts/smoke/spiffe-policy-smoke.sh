#!/usr/bin/env sh
set -eu

WORKLOAD_IDENTITY="spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"
POLICY_URL="https://airlock-control-plane.airlock-system.svc.cluster.local:8443/v1/policies"

kubectl rollout status deployment/airlock-control-plane -n airlock-system --timeout=180s
kubectl rollout status deployment/airlock-proxy-worker -n demo --timeout=180s

if kubectl exec -n demo deploy/code-agent -- \
  curl -kfsS --get \
    --data-urlencode "workload_identity=$WORKLOAD_IDENTITY" \
    "$POLICY_URL" >/dev/null 2>&1; then
  echo "unauthenticated policy request unexpectedly succeeded" >&2
  exit 1
fi

kubectl logs -n demo deploy/airlock-proxy-worker --tail=100 \
  | grep -q "policy_version=airlock.dev/v1alpha1"

kubectl logs -n airlock-system deploy/airlock-control-plane --tail=100 \
  | grep -q '"authMode":"spiffe"'

kubectl logs -n airlock-system deploy/airlock-control-plane --tail=100 \
  | grep -q "\"authenticatedIdentity\":\"$WORKLOAD_IDENTITY\""

echo "SPIFFE policy smoke passed"
