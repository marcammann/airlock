#!/usr/bin/env sh
set -eu

ENVOY_URL="${ENVOY_URL:-http://127.0.0.1:10000/healthz}"
ALLOWED_HOST="${ALLOWED_HOST:-echo-upstream.demo.svc.cluster.local:8080}"
WORKLOAD_LABEL="${WORKLOAD_LABEL:-app.kubernetes.io/name=code-agent}"
WORKLOAD_DEPLOYMENT="${WORKLOAD_DEPLOYMENT:-code-agent}"
CURL_ERROR_LOG="${TMPDIR:-/tmp}/airlock-fail-closed-curl.err"

latest_pod() {
  namespace="$1"
  label="$2"
  kubectl get pods -n "$namespace" -l "$label" --sort-by=.metadata.creationTimestamp --no-headers | awk 'END { print $1 }'
}

wait_for_replacement_pod() {
  namespace="$1"
  label="$2"
  old_pod="$3"
  for attempt in $(seq 1 60); do
    pod="$(latest_pod "$namespace" "$label")"
    if [ -n "$pod" ] && [ "$pod" != "$old_pod" ]; then
      printf '%s\n' "$pod"
      return 0
    fi
    sleep 1
  done
  kubectl get pods -n "$namespace" -l "$label" -o wide >&2 || true
  echo "timed out waiting for replacement pod for $label" >&2
  return 1
}

wait_for_container_running() {
  namespace="$1"
  pod="$2"
  container="$3"
  for attempt in $(seq 1 60); do
    started_at="$(kubectl get pod "$pod" -n "$namespace" -o jsonpath="{.status.containerStatuses[?(@.name==\"$container\")].state.running.startedAt}" 2>/dev/null || true)"
    if [ -n "$started_at" ]; then
      return 0
    fi
    sleep 1
  done
  kubectl describe pod "$pod" -n "$namespace" >&2 || true
  echo "timed out waiting for $pod/$container to run" >&2
  return 1
}

wait_for_proxy_log() {
  pod="$1"
  pattern="$2"
  for attempt in $(seq 1 60); do
    logs="$({
      kubectl logs -n demo "$pod" -c proxy-worker --tail=300 2>&1 || true
      kubectl logs -n demo "$pod" -c proxy-worker --previous --tail=300 2>&1 || true
    })"
    if printf '%s\n' "$logs" | grep -q "$pattern"; then
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$logs" >&2
  echo "timed out waiting for proxy-worker log pattern: $pattern" >&2
  return 1
}

envoy_upstream_requests() {
  pod="$1"
  kubectl exec -n demo "$pod" -c app -- \
    curl -fsS --max-time 5 "http://127.0.0.1:9901/stats?filter=cluster.echo_upstream.upstream_rq_total" 2>/dev/null |
    awk -F': ' '/cluster.echo_upstream.upstream_rq_total/ { print $2; found=1 } END { if (!found) print 0 }'
}

restart_workload_for_outage() {
  old_pod="$(latest_pod demo "$WORKLOAD_LABEL")"
  if [ -n "$old_pod" ]; then
    kubectl delete pod "$old_pod" -n demo --wait=false >/dev/null
  fi
  pod="$(wait_for_replacement_pod demo "$WORKLOAD_LABEL" "$old_pod")"
  wait_for_container_running demo "$pod" app
  wait_for_container_running demo "$pod" envoy
  printf '%s\n' "$pod"
}

assert_allowed_request_fails_without_upstream() {
  pod="$1"
  before="$(envoy_upstream_requests "$pod")"
  if kubectl exec -n demo "$pod" -c app -- \
    curl -fsS --max-time 10 -H "Host: $ALLOWED_HOST" "$ENVOY_URL" >/dev/null 2>"$CURL_ERROR_LOG"; then
    echo "allowed request unexpectedly succeeded during outage" >&2
    exit 1
  fi
  after="$(envoy_upstream_requests "$pod")"
  if [ "$after" != "$before" ]; then
    cat "$CURL_ERROR_LOG" >&2 || true
    echo "echo_upstream request count changed during fail-closed outage: before=$before after=$after" >&2
    exit 1
  fi
}

restore_cluster() {
  set +e
  kubectl scale deployment/vault-dev -n vault --replicas=1 >/dev/null 2>&1
  kubectl scale deployment/airlock-control-plane -n airlock-system --replicas=1 >/dev/null 2>&1
  kubectl rollout status deployment/vault-dev -n vault --timeout=120s >/dev/null 2>&1
  ./examples/k8s/vault-jwt-setup.sh >/dev/null 2>&1
  kubectl rollout status deployment/airlock-control-plane -n airlock-system --timeout=180s >/dev/null 2>&1
  kubectl rollout restart "deployment/$WORKLOAD_DEPLOYMENT" -n demo >/dev/null 2>&1
}

trap restore_cluster EXIT

SMOKE_NAME=fail-closed-baseline ./scripts/smoke/k8s-egress-smoke.sh

kubectl scale deployment/vault-dev -n vault --replicas=0
kubectl wait pod -n vault -l app.kubernetes.io/name=vault --for=delete --timeout=120s || true
vault_outage_pod="$(restart_workload_for_outage)"
assert_allowed_request_fails_without_upstream "$vault_outage_pod"
wait_for_proxy_log "$vault_outage_pod" "Vault JWT login failed"

kubectl scale deployment/vault-dev -n vault --replicas=1
kubectl rollout status deployment/vault-dev -n vault --timeout=120s
./examples/k8s/vault-jwt-setup.sh
kubectl rollout restart deployment/airlock-control-plane -n airlock-system
kubectl rollout status deployment/airlock-control-plane -n airlock-system --timeout=180s
kubectl rollout restart "deployment/$WORKLOAD_DEPLOYMENT" -n demo
kubectl rollout status "deployment/$WORKLOAD_DEPLOYMENT" -n demo --timeout=180s

kubectl scale deployment/airlock-control-plane -n airlock-system --replicas=0
kubectl wait pod -n airlock-system -l app.kubernetes.io/name=airlock-control-plane --for=delete --timeout=120s || true
control_plane_outage_pod="$(restart_workload_for_outage)"
assert_allowed_request_fails_without_upstream "$control_plane_outage_pod"
wait_for_proxy_log "$control_plane_outage_pod" "fetch policy over SPIFFE mTLS"

echo "fail-closed Kubernetes smoke passed"
