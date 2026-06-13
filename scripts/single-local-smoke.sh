#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
UPSTREAM_LOG="${TMPDIR:-/tmp}/airlock-single-local-upstream.$$"
PROXY_LOG="${TMPDIR:-/tmp}/airlock-single-local-proxy.$$"
UPSTREAM_PID=""
PROXY_PID=""

cleanup() {
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "$UPSTREAM_PID" ]; then
    kill "$UPSTREAM_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

wait_for_log() {
  file="$1"
  pattern="$2"
  for attempt in $(seq 1 60); do
    if [ -f "$file" ] && grep -q "$pattern" "$file"; then
      return 0
    fi
    sleep 1
  done
  cat "$file" >&2 || true
  echo "timed out waiting for log pattern: $pattern" >&2
  return 1
}

python3 -c '
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

log_path = sys.argv[1]

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(self.requestline + "\n")
            for name, value in self.headers.items():
                log.write(f"{name}: {value}\n")
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format, *args):
        return

HTTPServer(("127.0.0.1", 18081), Handler).serve_forever()
' "$UPSTREAM_LOG" &
UPSTREAM_PID="$!"

for attempt in $(seq 1 30); do
  if curl -fsS --max-time 1 http://127.0.0.1:18081/__ready >/dev/null 2>&1; then
    : >"$UPSTREAM_LOG"
    break
  fi
  if [ "$attempt" = "30" ]; then
    echo "timed out waiting for local upstream" >&2
    exit 1
  fi
  sleep 1
done

(
  cd "$ROOT_DIR/proxy-worker-rs"
  AIRLOCK_TEST_TOKEN=single-local-token cargo run -p airlock-proxy-worker -- \
    --no-control-plane \
    --policy ../fixtures/policies/local-http.yaml \
    --listen 127.0.0.1:18080
) >"$PROXY_LOG" 2>&1 &
PROXY_PID="$!"

wait_for_log "$PROXY_LOG" "proxy_type=builtin control_plane=disabled"
wait_for_log "$PROXY_LOG" "builtin proxy listening on 127.0.0.1:18080"

curl -fsS --max-time 10 --noproxy "" --proxy http://127.0.0.1:18080 \
  http://127.0.0.1:18081/v1/models >/dev/null

if curl -fsS --max-time 10 --noproxy "" --proxy http://127.0.0.1:18080 \
  http://denied.example.test/v1/models >/dev/null 2>&1; then
  echo "denied destination unexpectedly succeeded" >&2
  exit 1
fi

grep -q "Authorization: Bearer single-local-token" "$UPSTREAM_LOG"
grep -q "allowed request policy=local-http" "$PROXY_LOG"
grep -q "denied request policy=local-http" "$PROXY_LOG"
grep -q "Authorization.*\\[REDACTED\\]" "$PROXY_LOG"
if grep -q "single-local-token" "$PROXY_LOG"; then
  echo "proxy-worker logs leaked the local secret" >&2
  exit 1
fi

echo "single-local smoke passed"
