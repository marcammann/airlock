#!/usr/bin/env sh
set -eu

CONTROL_PLANE_PORT=18082
PROXY_PORT=18080
UPSTREAM_PORT=18081
WORKLOAD_IDENTITY="spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"

tmpdir="$(mktemp -d)"
control_plane_pid=""
proxy_pid=""
upstream_pid=""

cleanup() {
  if [ -n "$proxy_pid" ]; then
    kill "$proxy_pid" 2>/dev/null || true
  fi
  if [ -n "$control_plane_pid" ]; then
    kill "$control_plane_pid" 2>/dev/null || true
  fi
  if [ -n "$upstream_pid" ]; then
    kill "$upstream_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

python3 -m http.server "$UPSTREAM_PORT" --bind 127.0.0.1 \
  >"$tmpdir/upstream.log" 2>&1 &
upstream_pid=$!

(
  go run ./cmd/airlock-control-plane \
    --listen "127.0.0.1:$CONTROL_PLANE_PORT" \
    --worker-auth none \
    --insecure-dev-mode \
    --policy fixtures/policies/local-http.yaml \
    --workload fixtures/workloads/local-http.yaml
) >"$tmpdir/control-plane.log" 2>&1 &
control_plane_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "http://127.0.0.1:$CONTROL_PLANE_PORT/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$CONTROL_PLANE_PORT/readyz" >/dev/null

(
  AIRLOCK_TEST_TOKEN=local-control-plane-token go run ./cmd/airlock-proxy-worker \
    --proxy "http:builtin@127.0.0.1:$PROXY_PORT" \
    --control-plane-url "http://127.0.0.1:$CONTROL_PLANE_PORT" \
    --control-plane-auth none \
    --insecure-dev-mode \
    --workload-identity "$WORKLOAD_IDENTITY" \
    --heartbeat-interval 0
) >"$tmpdir/proxy-worker.log" 2>&1 &
proxy_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$UPSTREAM_PORT/" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

curl -fsS \
  --proxy "http://127.0.0.1:$PROXY_PORT" \
  "http://127.0.0.1:$UPSTREAM_PORT/" >/dev/null

grep -q "policy_version=airlock.dev/v1alpha1" "$tmpdir/proxy-worker.log"
grep -q '"effectivePolicyVersion":"airlock.dev/v1alpha1"' "$tmpdir/control-plane.log"

echo "local control-plane smoke passed"
