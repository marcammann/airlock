#!/bin/sh
set -eu

role="$1"
shift

case "$role" in
  control-plane)
    run_user="airlock-control"
    ;;
  proxy-worker)
    run_user="airlock-proxy"
    ;;
  *)
    echo "unknown Airlock SPIRE role: $role" >&2
    exit 2
    ;;
esac

socket_path="/run/spire/agent-sockets/spire-agent.sock"
token_file="/run/spire/bootstrap/${role}-token"

mkdir -p /run/spire/agent-sockets /run/spire/agent-data

spire-agent run \
  -config /run/spire/config/agent.conf \
  -joinToken "$(cat "$token_file")" \
  -insecureBootstrap &
agent_pid="$!"

cleanup() {
  kill "$agent_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 60); do
  if spire-agent healthcheck -socketPath "$socket_path" >/dev/null 2>&1; then
    chmod 0666 "$socket_path"
    exec su-exec "$run_user" "$@"
  fi
  sleep 1
done

echo "SPIRE agent did not become healthy" >&2
exit 1
