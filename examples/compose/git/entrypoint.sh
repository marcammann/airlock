#!/bin/sh
set -eu

AIRLOCK_RUN_ROLE="${AIRLOCK_RUN_ROLE:-combined-builtin}"
AIRLOCK_CONTROL_PLANE_URL="${AIRLOCK_CONTROL_PLANE_URL:-http://control-plane:8080}"
AIRLOCK_DEV_TOKEN="${AIRLOCK_DEV_TOKEN:-compose-dev-token}"
AIRLOCK_ADMIN_URL="${AIRLOCK_ADMIN_URL:-}"
AIRLOCK_OIDC_TOKEN_URL="${AIRLOCK_OIDC_TOKEN_URL:-http://oidc:8080/token}"
AIRLOCK_ADMIN_SMOKE="${AIRLOCK_ADMIN_SMOKE:-false}"
AIRLOCK_NO_CONTROL_PLANE="${AIRLOCK_NO_CONTROL_PLANE:-false}"
AIRLOCK_POLICY_PATH="${AIRLOCK_POLICY_PATH:-/airlock/policies/github.yaml}"
AIRLOCK_PROXY_LISTEN="${AIRLOCK_PROXY_LISTEN:-127.0.0.1:18080}"
AIRLOCK_HEARTBEAT_INTERVAL="${AIRLOCK_HEARTBEAT_INTERVAL:-2s}"
AIRLOCK_GIT_PROXY_URL="${AIRLOCK_GIT_PROXY_URL:-}"
AIRLOCK_WORKLOAD_ID="${AIRLOCK_WORKLOAD_ID:-spiffe://airlock.local/compose/git-checkout/component/airlock-proxy-worker}"
AIRLOCK_CA_CERT="${AIRLOCK_CA_CERT:-/run/airlock/ca/ca.crt}"
AIRLOCK_CA_KEY="${AIRLOCK_CA_KEY:-/run/airlock/ca/ca.key}"
AIRLOCK_SECRET_FILE="${AIRLOCK_SECRET_FILE:-/run/airlock/secrets/github-basic-auth}"
GITHUB_BASIC_USER="${GITHUB_BASIC_USER:-x-access-token}"
GITHUB_HOST="${GITHUB_HOST:-github.com}"
GITHUB_REPO="${GITHUB_REPO:-marcammann/portfolio}"
GIT_DEPTH="${GIT_DEPTH:-1}"
EXPECT_DIRECT_CLONE_DENIED="${EXPECT_DIRECT_CLONE_DENIED:-true}"

if [ -z "$AIRLOCK_GIT_PROXY_URL" ]; then
  AIRLOCK_GIT_PROXY_URL="http://$AIRLOCK_PROXY_LISTEN"
fi

github_basic_auth=""

require_pat() {
  if [ -z "${GITHUB_PAT:-}" ]; then
    echo "GITHUB_PAT is required" >&2
    exit 2
  fi
}

write_github_secret() {
  require_pat
  umask 077
  github_basic_auth="$(printf "%s:%s" "$GITHUB_BASIC_USER" "$GITHUB_PAT" | base64 | tr -d '\n')"
  mkdir -p "$(dirname "$AIRLOCK_SECRET_FILE")"
  printf "%s" "$github_basic_auth" >"$AIRLOCK_SECRET_FILE"
  chown airlock:airlock "$AIRLOCK_SECRET_FILE"
  chmod 0400 "$AIRLOCK_SECRET_FILE"
  unset GITHUB_PAT
}

generate_ca() {
  mkdir -p "$(dirname "$AIRLOCK_CA_CERT")" "$(dirname "$AIRLOCK_CA_KEY")"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$AIRLOCK_CA_KEY" \
    -out "$AIRLOCK_CA_CERT" \
    -days 1 \
    -subj "/CN=airlock docker compose git ca" >/dev/null 2>&1
  chown airlock:airlock "$AIRLOCK_CA_KEY"
  chmod 0400 "$AIRLOCK_CA_KEY"
  chmod 0444 "$AIRLOCK_CA_CERT"
}

wait_for_url() {
  url="$1"
  name="$2"
  for attempt in $(seq 1 60); do
    if wget -q -O /dev/null "$url"; then
      return 0
    fi
    if [ "$attempt" = "60" ]; then
      echo "$name did not become ready" >&2
      return 1
    fi
    sleep 1
  done
}

wait_for_tcp() {
  host_port="${1#http://}"
  host_port="${host_port#https://}"
  host_port="${host_port%%/*}"
  host="${host_port%:*}"
  port="${host_port##*:}"
  name="$2"
  for attempt in $(seq 1 60); do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    if [ "$attempt" = "60" ]; then
      echo "$name did not become ready" >&2
      return 1
    fi
    sleep 1
  done
}

run_proxy() {
  mode="$1"
  set -- \
    airlock-proxy-worker \
    --proxy "http:${mode}@${AIRLOCK_PROXY_LISTEN}" \
    --mitm-ca-cert "$AIRLOCK_CA_CERT" \
    --mitm-ca-key "$AIRLOCK_CA_KEY"

  if [ "$AIRLOCK_NO_CONTROL_PLANE" = "true" ]; then
    set -- "$@" --no-control-plane --policy "$AIRLOCK_POLICY_PATH"
  else
    wait_for_url "$AIRLOCK_CONTROL_PLANE_URL/readyz" "control plane"
    set -- "$@" \
      --control-plane-url "$AIRLOCK_CONTROL_PLANE_URL" \
      --control-plane-auth dev-token \
      --dev-token "$AIRLOCK_DEV_TOKEN" \
      --insecure-dev-mode \
      --workload-identity "$AIRLOCK_WORKLOAD_ID" \
      --heartbeat-interval "$AIRLOCK_HEARTBEAT_INTERVAL"
  fi

  su-exec airlock:airlock "$@"
}

start_proxy() {
  mode="$1"
  run_proxy "$mode" &
  proxy_pid="$!"
  cleanup() {
    kill "$proxy_pid" 2>/dev/null || true
  }
  trap cleanup EXIT INT TERM
  wait_for_tcp "http://${AIRLOCK_PROXY_LISTEN}" "airlock proxy"
}

check_app_cannot_read_airlock_files() {
  if [ -e "$AIRLOCK_SECRET_FILE" ] && su-exec appuser:appuser test -r "$AIRLOCK_SECRET_FILE"; then
    echo "appuser can read the Airlock GitHub credential file" >&2
    exit 1
  fi
  if [ -e "$AIRLOCK_CA_KEY" ] && su-exec appuser:appuser test -r "$AIRLOCK_CA_KEY"; then
    echo "appuser can read the Airlock MITM CA private key" >&2
    exit 1
  fi
}

run_git_checkout() {
  wait_for_tcp "$AIRLOCK_GIT_PROXY_URL" "git proxy"
  for attempt in $(seq 1 60); do
    if [ -r "$AIRLOCK_CA_CERT" ]; then
      break
    fi
    if [ "$attempt" = "60" ]; then
      echo "Airlock public CA was not available to the app" >&2
      exit 1
    fi
    sleep 1
  done

  rm -rf /work/repo /work/direct
  chown -R appuser:appuser /work
  check_app_cannot_read_airlock_files

  if [ "$EXPECT_DIRECT_CLONE_DENIED" = "true" ]; then
    if su-exec appuser:appuser env -i \
      HOME=/home/appuser \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      GIT_TERMINAL_PROMPT=0 \
      git \
        -c http.proxy= \
        -c https.proxy= \
        -c credential.helper= \
        clone --depth "$GIT_DEPTH" "https://${GITHUB_HOST}/${GITHUB_REPO}.git" /work/direct >/work/git-direct.log 2>&1; then
      echo "direct git clone unexpectedly succeeded without Airlock-injected credentials" >&2
      exit 1
    fi
  fi

  su-exec appuser:appuser env -i \
    HOME=/home/appuser \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GIT_TERMINAL_PROMPT=0 \
    git \
      -c "http.proxy=${AIRLOCK_GIT_PROXY_URL}" \
      -c "https.proxy=${AIRLOCK_GIT_PROXY_URL}" \
      -c "http.sslCAInfo=${AIRLOCK_CA_CERT}" \
      -c credential.helper= \
      clone --depth "$GIT_DEPTH" "https://${GITHUB_HOST}/${GITHUB_REPO}.git" /work/repo >/work/git-clone.log 2>&1

  if [ ! -d /work/repo/.git ]; then
    echo "proxied git clone did not produce /work/repo/.git" >&2
    exit 1
  fi

  if [ -n "$github_basic_auth" ]; then
    for log_path in /work/git-clone.log /work/git-direct.log; do
      if [ -e "$log_path" ] && grep -F "$github_basic_auth" "$log_path" >/dev/null 2>&1; then
        echo "git logs leaked derived GitHub Basic auth payload" >&2
        exit 1
      fi
    done
  fi

  echo "airlock Compose git checkout succeeded: ${GITHUB_REPO}"
}

run_admin_smoke() {
  if [ "$AIRLOCK_ADMIN_SMOKE" != "true" ]; then
    return 0
  fi
  if [ -z "$AIRLOCK_ADMIN_URL" ]; then
    echo "AIRLOCK_ADMIN_URL is required when AIRLOCK_ADMIN_SMOKE=true" >&2
    exit 2
  fi

  wait_for_url "$AIRLOCK_ADMIN_URL/readyz" "control-plane admin API"

  admin_token="$(wget -q -O - "$AIRLOCK_OIDC_TOKEN_URL")"
  if [ -z "$admin_token" ]; then
    echo "OIDC demo issuer returned an empty admin token" >&2
    exit 1
  fi

  if ! wget -q -O /work/airlock-admin-workloads.json \
    --header "Authorization: Bearer ${admin_token}" \
    "$AIRLOCK_ADMIN_URL/v1/admin/workloads"; then
    echo "admin OIDC/RBAC workload read failed" >&2
    exit 1
  fi
  if ! grep -F "compose-github-checkout" /work/airlock-admin-workloads.json >/dev/null 2>&1; then
    echo "admin workload response did not include the git-checkout workload" >&2
    cat /work/airlock-admin-workloads.json >&2
    exit 1
  fi

  for attempt in $(seq 1 30); do
    if wget -q -O /work/airlock-admin-proxies.json \
      --header "Authorization: Bearer ${admin_token}" \
      "$AIRLOCK_ADMIN_URL/v1/admin/proxies" &&
      grep -F "$AIRLOCK_WORKLOAD_ID" /work/airlock-admin-proxies.json >/dev/null 2>&1 &&
      grep -F '"status":"active"' /work/airlock-admin-proxies.json >/dev/null 2>&1; then
      break
    fi
    if [ "$attempt" = "30" ]; then
      echo "admin proxy response did not include an active proxy heartbeat" >&2
      cat /work/airlock-admin-proxies.json >&2 || true
      exit 1
    fi
    sleep 1
  done

  bad_token="$(wget -q -O - "${AIRLOCK_OIDC_TOKEN_URL}?group=not-airlock")"
  if wget -q -O /work/airlock-admin-forbidden.json \
    --header "Authorization: Bearer ${bad_token}" \
    "$AIRLOCK_ADMIN_URL/v1/admin/workloads"; then
    echo "admin OIDC/RBAC unexpectedly allowed an unmapped group" >&2
    exit 1
  fi

  echo "airlock Compose admin OIDC/RBAC smoke succeeded"
}

case "$AIRLOCK_RUN_ROLE" in
  combined-builtin)
    write_github_secret
    generate_ca
    start_proxy builtin
    run_git_checkout
    run_admin_smoke
    ;;
  proxy-envoy)
    write_github_secret
    generate_ca
    run_proxy envoy
    ;;
  git-client)
    run_git_checkout
    run_admin_smoke
    ;;
  *)
    echo "unsupported AIRLOCK_RUN_ROLE=$AIRLOCK_RUN_ROLE" >&2
    exit 2
    ;;
esac
