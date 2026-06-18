#!/bin/sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
IMAGE="${AIRLOCK_DAYTONA_IMAGE:-airlock-daytona-soft-sandbox:dev}"
ARTIFACT_IMAGE="${AIRLOCK_ARTIFACT_IMAGE:-ghcr.io/marcammann/airlock:dev}"
SECRET_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$SECRET_DIR"
}
trap cleanup EXIT INT TERM

if [ -n "${OPENAI_API_KEY:-}" ]; then
  printf "OPENAI_API_KEY=%s\n" "$OPENAI_API_KEY" >"$SECRET_DIR/secrets.env"
  live_check='curl -fsS https://api.openai.com/v1/models >/tmp/openai-models.json; test -s /tmp/openai-models.json; echo "airlock Daytona soft sandbox live egress smoke succeeded"'
else
  printf "%s\n" "OPENAI_API_KEY=dummy-local-smoke-token" >"$SECRET_DIR/secrets.env"
  live_check='echo "airlock Daytona soft sandbox permission smoke succeeded; set OPENAI_API_KEY to run the live OpenAI egress check"'
fi
chmod 0400 "$SECRET_DIR/secrets.env"

docker buildx build --load \
  -t "$ARTIFACT_IMAGE" \
  "$ROOT_DIR"

docker buildx build --load \
  --build-arg AIRLOCK_ARTIFACT_IMAGE="$ARTIFACT_IMAGE" \
  -f "$ROOT_DIR/examples/daytona/soft-sandbox/Dockerfile" \
  -t "$IMAGE" \
  "$ROOT_DIR/examples/daytona/soft-sandbox"

docker run --rm -i \
  --entrypoint /bin/sh \
  "$IMAGE" \
  -ec '
    cat > /run/daytona-secrets/secrets.env
    sudo -n -u airlock -- /usr/local/bin/airlock-daytona-start-proxy &
    for attempt in $(seq 1 60); do
      if nc -z 127.0.0.1 18080; then
        break
      fi
      if [ "$attempt" = 60 ]; then
        sed -n '"'"'1,160p'"'"' /var/log/airlock/proxy-worker.log 2>&1 || true
        exit 1
      fi
      sleep 1
    done
    sh -lc '"'"'
    test ! -r /run/daytona-secrets/secrets.env
    test ! -r /run/airlock/secrets/openai-api-key
    test ! -r /run/airlock/ca/ca.key
    openssl x509 -in /run/airlock/ca/ca.crt -noout -text | grep -q "CA:TRUE"
    openssl x509 -in /run/airlock/ca/ca.crt -noout -text | grep -q "Certificate Sign"
    openssl x509 -in /run/airlock/ca/ca.crt -noout -text | grep -q "CRL Sign"
    nc -z 127.0.0.1 18080
    '"$live_check"'
    '"'"'
  ' <"$SECRET_DIR/secrets.env"
