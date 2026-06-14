#!/usr/bin/env sh
set -eu

KUSTOMIZE_DIR="${KUSTOMIZE_DIR:-deploy/k8s}"
EXAMPLE_KUSTOMIZE_DIR="${EXAMPLE_KUSTOMIZE_DIR:-examples/k8s/basic-egress}"
SMOKE_NAME="${SMOKE_NAME:-k8s-egress}"
ENVOY_URL="${ENVOY_URL:-http://127.0.0.1:10000/healthz}"
ALLOWED_HOST="${ALLOWED_HOST:-echo-upstream.demo.svc.cluster.local:8080}"
VAULT_SECRET_VALUE="${VAULT_SECRET_VALUE:-vault-smoke-token}"
WORKLOAD_DEPLOYMENT="${WORKLOAD_DEPLOYMENT:-code-agent}"
WORKLOAD_LABEL="${WORKLOAD_LABEL:-app.kubernetes.io/name=code-agent}"
WORKLOAD_MANIFEST="${WORKLOAD_MANIFEST:-}"
ALLOW_SOURCE_ENVOY="${ALLOW_SOURCE_ENVOY:-false}"
CURL_ERROR_LOG="${TMPDIR:-/tmp}/airlock-k8s-egress-curl.err"
CONTROL_PLANE_POD=""
CODE_AGENT_POD=""

wait_for_proxy_log() {
  pattern="$1"
  for attempt in $(seq 1 30); do
    if kubectl logs -n demo "$CODE_AGENT_POD" -c proxy-worker --tail=300 | grep -q "$pattern"; then
      return 0
    fi
    sleep 1
  done
  kubectl logs -n demo "$CODE_AGENT_POD" -c proxy-worker --tail=300 >&2 || true
  echo "timed out waiting for proxy-worker log pattern: $pattern" >&2
  return 1
}

wait_for_vault_log() {
  pattern="$1"
  for attempt in $(seq 1 30); do
    if kubectl logs -n vault deploy/vault-dev --tail=500 | grep -q "$pattern"; then
      return 0
    fi
    sleep 1
  done
  kubectl logs -n vault deploy/vault-dev --tail=500 >&2 || true
  echo "timed out waiting for Vault log pattern: $pattern" >&2
  return 1
}

wait_for_control_plane_log() {
  pattern="$1"
  for attempt in $(seq 1 30); do
    if kubectl logs -n airlock-system "$CONTROL_PLANE_POD" --tail=300 | grep -q "$pattern"; then
      return 0
    fi
    sleep 1
  done
  kubectl logs -n airlock-system "$CONTROL_PLANE_POD" --tail=300 >&2 || true
  echo "timed out waiting for control-plane log pattern: $pattern" >&2
  return 1
}

envoy_downstream_requests() {
  kubectl exec -n demo "$CODE_AGENT_POD" -c app -- \
    curl -fsS --max-time 5 "http://127.0.0.1:9901/stats?filter=http.airlock_egress.downstream_rq_total" 2>/dev/null |
    awk -F': ' '/http.airlock_egress.downstream_rq_total/ { print $2; found=1 } END { if (!found) print 0 }'
}

assert_managed_proxy_env_path() {
  kubectl exec -n demo "$CODE_AGENT_POD" -c app -- sh -c '
    test "${http_proxy:-}" = "http://127.0.0.1:10000" &&
    test "${https_proxy:-}" = "http://127.0.0.1:10000" &&
    test "${NO_PROXY:-}" = "127.0.0.1,localhost,::1"
  '

  before="$(envoy_downstream_requests)"
  if ! kubectl exec -n demo "$CODE_AGENT_POD" -c app -- \
    curl -fsS --max-time 10 "http://$ALLOWED_HOST/healthz" >/dev/null 2>"$CURL_ERROR_LOG"; then
    cat "$CURL_ERROR_LOG" >&2 || true
    kubectl logs -n demo "$CODE_AGENT_POD" -c envoy --tail=120 >&2 || true
    echo "managed proxy env request failed" >&2
    exit 1
  fi
  after="$(envoy_downstream_requests)"
  if [ "$after" -le "$before" ]; then
    echo "managed proxy env request did not increment Envoy downstream requests: before=$before after=$after" >&2
    exit 1
  fi
}

./examples/k8s/vault-jwt-setup.sh

if [ -d "$KUSTOMIZE_DIR/crds" ]; then
  kubectl apply -f "$KUSTOMIZE_DIR/crds"
  kubectl wait --for=condition=Established crd/airlockpolicies.airlock.dev --timeout=60s
  kubectl wait --for=condition=Established crd/secretproviderconfigs.airlock.dev --timeout=60s
fi

kubectl apply -k "$KUSTOMIZE_DIR"
kubectl apply -k "$EXAMPLE_KUSTOMIZE_DIR"
kubectl delete deployment airlock-proxy-worker -n demo --ignore-not-found
kubectl delete clusterspiffeid airlock-proxy-worker --ignore-not-found
kubectl rollout restart deployment/airlock-control-plane -n airlock-system
kubectl rollout status deployment/vault-dev -n vault --timeout=120s
kubectl rollout status deployment/airlock-control-plane -n airlock-system --timeout=180s
for attempt in $(seq 1 30); do
  if kubectl get clusterspiffeid airlock-code-agent >/dev/null 2>&1; then
    break
  fi
  if [ "$attempt" = "30" ]; then
    kubectl get clusterspiffeids -o yaml >&2 || true
    echo "ClusterSPIFFEID/airlock-code-agent was not reconciled" >&2
    exit 1
  fi
  sleep 1
done
if [ -n "$WORKLOAD_MANIFEST" ]; then
  kubectl delete deployment "$WORKLOAD_DEPLOYMENT" -n demo --ignore-not-found
  kubectl apply -f "$WORKLOAD_MANIFEST"
else
  kubectl rollout restart "deployment/$WORKLOAD_DEPLOYMENT" -n demo
fi
kubectl rollout status "deployment/$WORKLOAD_DEPLOYMENT" -n demo --timeout=180s
kubectl rollout status deployment/echo-upstream -n demo --timeout=120s

CONTROL_PLANE_POD="$(kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock-control-plane --sort-by=.metadata.creationTimestamp --no-headers | awk 'END { print $1 }')"
CODE_AGENT_POD="$(kubectl get pods -n demo -l "$WORKLOAD_LABEL" --sort-by=.metadata.creationTimestamp --no-headers | awk 'END { print $1 }')"

wait_for_control_plane_log "vault_reconcile"
wait_for_control_plane_log "reconciled Vault intent: policies=1 roles=1"

for attempt in $(seq 1 30); do
  ready_status="$(kubectl get airlockworkload code-agent -n airlock-system -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  if [ "$ready_status" = "True" ]; then
    break
  fi
  if [ "$attempt" = "30" ]; then
    kubectl get airlockworkload code-agent -n airlock-system -o yaml >&2 || true
    echo "AirlockWorkload/code-agent did not become Ready" >&2
    exit 1
  fi
  sleep 1
done

deny_capabilities="$(kubectl exec -n vault deploy/vault-dev -- sh -c 'export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root; token="$(vault token create -policy=airlock-code-agent -field=token)" && VAULT_TOKEN="$token" vault token capabilities secret/data/airlock/openai/not-allowed')"
printf '%s\n' "$deny_capabilities" | grep -qx "deny"

if kubectl get "deployment/$WORKLOAD_DEPLOYMENT" -n demo -o yaml | grep -q -- "--vault-"; then
  echo "$WORKLOAD_DEPLOYMENT proxy-worker sidecar still contains Vault CLI flags" >&2
  exit 1
fi

wait_for_proxy_log "vault: fetched jwt-svid"
wait_for_proxy_log "vault: authenticated role=airlock-demo-code-agent"
wait_for_proxy_log "vault: preloaded secret mount=secret path=airlock/openai/code-agent key=api_key"
wait_for_proxy_log "envoy mode listening on 127.0.0.1:50051"

kubectl wait -n demo --for=condition=Ready "pod/$CODE_AGENT_POD" --timeout=60s
if [ -n "$WORKLOAD_MANIFEST" ]; then
  source_containers="$(kubectl get "deployment/$WORKLOAD_DEPLOYMENT" -n demo -o jsonpath='{.spec.template.spec.containers[*].name}')"
  if printf '%s\n' "$source_containers" | grep -Eq '(^| )proxy-worker( |$)'; then
    echo "$WORKLOAD_DEPLOYMENT manifest unexpectedly contains the Airlock proxy-worker sidecar" >&2
    exit 1
  fi
  if [ "$ALLOW_SOURCE_ENVOY" != "true" ] && printf '%s\n' "$source_containers" | grep -Eq '(^| )envoy( |$)'; then
    echo "$WORKLOAD_DEPLOYMENT manifest unexpectedly contains an Envoy sidecar" >&2
    exit 1
  fi
  if [ "$ALLOW_SOURCE_ENVOY" = "true" ] && ! printf '%s\n' "$source_containers" | grep -Eq '(^| )envoy( |$)'; then
    echo "$WORKLOAD_DEPLOYMENT manifest should contain an externally managed Envoy sidecar" >&2
    exit 1
  fi
  admitted_containers="$(kubectl get pod "$CODE_AGENT_POD" -n demo -o jsonpath='{.spec.containers[*].name}')"
  printf '%s\n' "$admitted_containers" | grep -Eq '(^| )envoy( |$)'
  printf '%s\n' "$admitted_containers" | grep -Eq '(^| )proxy-worker( |$)'
  if [ "$ALLOW_SOURCE_ENVOY" != "true" ]; then
    assert_managed_proxy_env_path
  fi
fi

for attempt in $(seq 1 30); do
  if kubectl exec -n demo "$CODE_AGENT_POD" -c app -- curl -fsS --max-time 10 -H "Host: $ALLOWED_HOST" "$ENVOY_URL" >/dev/null 2>"$CURL_ERROR_LOG"; then
    break
  fi
  if [ "$attempt" = "30" ]; then
    cat "$CURL_ERROR_LOG" >&2 || true
    kubectl logs -n demo "$CODE_AGENT_POD" -c envoy --tail=120 >&2 || true
    exit 1
  fi
  sleep 1
done

if kubectl exec -n demo "$CODE_AGENT_POD" -c app -- curl -fsS --max-time 10 -H "Host: denied.example.test" "$ENVOY_URL" >/dev/null 2>"$CURL_ERROR_LOG"; then
  echo "denied destination unexpectedly succeeded" >&2
  exit 1
fi

wait_for_proxy_log "allowed ext_proc request policy=code-agent"
wait_for_proxy_log "denied ext_proc request policy=code-agent"
wait_for_proxy_log "Authorization.*\\[REDACTED\\]"
if kubectl logs -n demo "$CODE_AGENT_POD" -c proxy-worker --tail=300 | grep -q "$VAULT_SECRET_VALUE"; then
  echo "proxy-worker logs leaked the Vault secret" >&2
  exit 1
fi

wait_for_vault_log "auth/jwt/login"

echo "$SMOKE_NAME smoke passed"
