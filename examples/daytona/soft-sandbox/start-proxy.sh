#!/bin/sh
set -eu

AIRLOCK_PROXY_LISTEN="${AIRLOCK_PROXY_LISTEN:-127.0.0.1:18080}"
AIRLOCK_POLICY_PATH="${AIRLOCK_POLICY_PATH:-/opt/airlock/policies/openai-api.yaml}"
AIRLOCK_SECRET_BUNDLE="${AIRLOCK_SECRET_BUNDLE:-/run/daytona-secrets/secrets.env}"
AIRLOCK_SECRET_DIR="${AIRLOCK_SECRET_DIR:-/run/airlock/secrets}"
AIRLOCK_CA_CERT="${AIRLOCK_CA_CERT:-/run/airlock/ca/ca.crt}"
AIRLOCK_CA_KEY="${AIRLOCK_CA_KEY:-/run/airlock/ca/ca.key}"
AIRLOCK_LOG_DIR="${AIRLOCK_LOG_DIR:-/var/log/airlock}"
AIRLOCK_PROXY_LOG="${AIRLOCK_PROXY_LOG:-$AIRLOCK_LOG_DIR/proxy-worker.log}"
AIRLOCK_SECRET_WAIT_TIMEOUT="${AIRLOCK_SECRET_WAIT_TIMEOUT:-300}"

log() {
  printf 'airlock-daytona-start-proxy: %s\n' "$*" >&2
}

secret_file_name() {
  printf '%s' "$1" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_' 'abcdefghijklmnopqrstuvwxyz-'
}

wait_for_secret_bundle() {
  log "waiting up to ${AIRLOCK_SECRET_WAIT_TIMEOUT}s for $AIRLOCK_SECRET_BUNDLE"
  elapsed=0
  while [ "$elapsed" -lt "$AIRLOCK_SECRET_WAIT_TIMEOUT" ]; do
    if [ -s "$AIRLOCK_SECRET_BUNDLE" ]; then
      return 0
    fi
    elapsed=$((elapsed + 1))
    sleep 1
  done

  if [ ! -s "$AIRLOCK_SECRET_BUNDLE" ]; then
    echo "missing Airlock secret bundle: $AIRLOCK_SECRET_BUNDLE" >&2
    echo "write KEY=value secrets there before starting the sandbox" >&2
    exit 2
  fi
}

install_secrets() {
  wait_for_secret_bundle
  log "installing secrets from $AIRLOCK_SECRET_BUNDLE"
  secret_count=0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
    "" | \#*) continue ;;
    esac

    case "$line" in
    *=*) ;;
    *)
      echo "invalid Airlock secret line: expected KEY=value" >&2
      exit 2
      ;;
    esac

    secret_name="${line%%=*}"
    secret_value="${line#*=}"
    case "$secret_name" in
    "" | *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_]*)
      echo "invalid Airlock secret name: $secret_name" >&2
      exit 2
      ;;
    esac

    secret_file="$AIRLOCK_SECRET_DIR/$(secret_file_name "$secret_name")"
    printf '%s' "$secret_value" >"$secret_file"
    chmod 0400 "$secret_file"
    secret_count=$((secret_count + 1))
  done <"$AIRLOCK_SECRET_BUNDLE"

  if [ "$secret_count" -eq 0 ]; then
    echo "Airlock secret bundle did not contain any secrets" >&2
    exit 2
  fi

  log "installed $secret_count Airlock-only secret(s) in $AIRLOCK_SECRET_DIR"
}

generate_ca() {
  log "generating local Airlock MITM CA"
  if [ ! -s "$AIRLOCK_CA_CERT" ] || [ ! -s "$AIRLOCK_CA_KEY" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$AIRLOCK_CA_KEY" \
      -out "$AIRLOCK_CA_CERT" \
      -days 1 \
      -sha256 \
      -subj "/CN=airlock daytona soft sandbox ca" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1
  fi

  chmod 0400 "$AIRLOCK_CA_KEY"
  chmod 0444 "$AIRLOCK_CA_CERT"
  log "generated public Airlock CA at $AIRLOCK_CA_CERT"
}

install_secrets
generate_ca

exec /opt/airlock/bin/airlock-proxy-worker \
  --proxy "http:builtin@${AIRLOCK_PROXY_LISTEN}" \
  --mitm-ca-cert "$AIRLOCK_CA_CERT" \
  --mitm-ca-key "$AIRLOCK_CA_KEY" \
  --no-control-plane \
  --policy "$AIRLOCK_POLICY_PATH" \
  --event-report disabled >>"$AIRLOCK_PROXY_LOG" 2>&1
