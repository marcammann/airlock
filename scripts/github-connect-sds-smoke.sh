#!/usr/bin/env sh
set -eu

NAMESPACE="${NAMESPACE:-demo}"
APP_NAME="${APP_NAME:-airlock-github-connect-smoke}"
PROXY_IMAGE="${PROXY_WORKER_IMAGE:-airlock-proxy-worker:dev}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.31.0}"
GIT_IMAGE="${GIT_IMAGE:-alpine/git:latest}"
GITHUB_HOST="${GITHUB_HOST:-github.com}"
GITHUB_REPO="${GITHUB_REPO:-marcammann/portfolio}"
GITHUB_BASIC_USER="${GITHUB_BASIC_USER:-x-access-token}"
OPENSSL="${OPENSSL:-openssl}"
RUN_ID="$(date +%s)"

if [ -z "${GITHUB_PAT:-}" ]; then
  echo "GITHUB_PAT is required to run the GitHub CONNECT SDS smoke" >&2
  exit 2
fi

if ! command -v "$OPENSSL" >/dev/null 2>&1; then
  if [ -x /opt/homebrew/bin/openssl ]; then
    OPENSSL=/opt/homebrew/bin/openssl
  fi
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/airlock-github-connect-smoke.XXXXXX")"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

umask 077

"$OPENSSL" req -x509 -newkey rsa:2048 -nodes \
  -keyout "$tmpdir/ca.key" \
  -out "$tmpdir/ca.crt" \
  -days 1 \
  -subj "/CN=airlock github connect smoke ca" >/dev/null 2>&1

printf "%s:%s" "$GITHUB_BASIC_USER" "$GITHUB_PAT" | base64 | tr -d '\n' >"$tmpdir/github-basic-auth"

cat >"$tmpdir/policy.yaml" <<EOF
apiVersion: airlock.dev/v1alpha1
kind: AirlockPolicy
metadata:
  name: github-connect-smoke
spec:
  workload:
    spiffeId: spiffe://airlock.local/ns/${NAMESPACE}/sa/${APP_NAME}/component/airlock-proxy-worker
    namespace: ${NAMESPACE}
    serviceAccount: ${APP_NAME}
  egress:
    - name: github-https
      scheme: https
      host: ${GITHUB_HOST}
      port: 443
      rewrites:
        - target: header
          name: Authorization
          valueTemplate: "Basic {{secret}}"
          valueFrom:
            provider: env
            name: github-basic-auth
            env: GITHUB_BASIC_AUTH
EOF

cat >"$tmpdir/envoy.yaml" <<EOF
node:
  id: ${APP_NAME}
  cluster: airlock
bootstrap_extensions:
  - name: envoy.bootstrap.internal_listener
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener
static_resources:
  listeners:
    - name: airlock_connect_proxy
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 10000
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: airlock_github_connect_proxy
                route_config:
                  name: airlock_github_connect_proxy_route
                  virtual_hosts:
                    - name: connect_proxy
                      domains: ["*"]
                      routes:
                        - match:
                            connect_matcher: {}
                          route:
                            cluster: airlock_connect_inner
                            upgrade_configs:
                              - upgrade_type: CONNECT
                                connect_config: {}
                upgrade_configs:
                  - upgrade_type: CONNECT
                http_filters:
                  - name: envoy.filters.http.ext_proc
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
                      failure_mode_allow: false
                      grpc_service:
                        envoy_grpc:
                          cluster_name: airlock_worker
                        timeout: 2s
                      processing_mode:
                        request_header_mode: SEND
                        response_header_mode: SKIP
                        request_body_mode: NONE
                        response_body_mode: NONE
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    - name: airlock_connect_inner
      internal_listener: {}
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: ${GITHUB_HOST}
                    sds_config:
                      resource_api_version: V3
                      api_config_source:
                        api_type: GRPC
                        transport_api_version: V3
                        grpc_services:
                          - envoy_grpc:
                              cluster_name: airlock_worker
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: airlock_github_connect_inner
                route_config:
                  name: airlock_github_connect_inner_route
                  virtual_hosts:
                    - name: github
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: github_upstream
                http_filters:
                  - name: envoy.filters.http.ext_proc
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
                      failure_mode_allow: false
                      grpc_service:
                        envoy_grpc:
                          cluster_name: airlock_worker
                        timeout: 2s
                      processing_mode:
                        request_header_mode: SEND
                        response_header_mode: SKIP
                        request_body_mode: NONE
                        response_body_mode: NONE
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: airlock_worker
      type: STRICT_DNS
      connect_timeout: 1s
      http2_protocol_options: {}
      load_assignment:
        cluster_name: airlock_worker
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 50051
    - name: airlock_connect_inner
      type: STATIC
      connect_timeout: 1s
      load_assignment:
        cluster_name: airlock_connect_inner
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    envoy_internal_address:
                      server_listener_name: airlock_connect_inner
    - name: github_upstream
      type: LOGICAL_DNS
      dns_lookup_family: V4_ONLY
      connect_timeout: 5s
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: ${GITHUB_HOST}
          common_tls_context:
            validation_context:
              trusted_ca:
                filename: /etc/ssl/certs/ca-certificates.crt
      load_assignment:
        cluster_name: github_upstream
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: ${GITHUB_HOST}
                      port_value: 443
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
EOF

kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE" >/dev/null

kubectl -n "$NAMESPACE" create secret generic airlock-github-ca-public \
  --from-file=ca.crt="$tmpdir/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create secret generic airlock-github-ca-private \
  --from-file=ca.key="$tmpdir/ca.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create secret generic airlock-github-basic-auth \
  --from-file=GITHUB_BASIC_AUTH="$tmpdir/github-basic-auth" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create configmap airlock-github-policy \
  --from-file=policy.yaml="$tmpdir/policy.yaml" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create configmap airlock-github-envoy \
  --from-file=envoy.yaml="$tmpdir/envoy.yaml" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

cat >"$tmpdir/workload.yaml" <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${APP_NAME}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: ${APP_NAME}
    app.kubernetes.io/part-of: airlock
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${APP_NAME}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: ${APP_NAME}
    app.kubernetes.io/part-of: airlock
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ${APP_NAME}
  template:
    metadata:
      annotations:
        airlock.dev/smoke-run: "${RUN_ID}"
      labels:
        app.kubernetes.io/name: ${APP_NAME}
        app.kubernetes.io/part-of: airlock
    spec:
      serviceAccountName: ${APP_NAME}
      containers:
        - name: app
          image: ${GIT_IMAGE}
          command:
            - sleep
            - infinity
          env:
            - name: GIT_TERMINAL_PROMPT
              value: "0"
          volumeMounts:
            - name: mitm-ca-public
              mountPath: /airlock/ca
              readOnly: true
        - name: envoy
          image: ${ENVOY_IMAGE}
          args:
            - -c
            - /etc/envoy/envoy.yaml
            - --log-level
            - info
          ports:
            - name: proxy
              containerPort: 10000
          volumeMounts:
            - name: envoy-config
              mountPath: /etc/envoy
              readOnly: true
        - name: proxy-worker
          image: ${PROXY_IMAGE}
          imagePullPolicy: Never
          args:
            - --proxy
            - http:envoy@127.0.0.1:50051
            - --no-control-plane
            - --policy
            - /airlock/policy/policy.yaml
            - --mitm-ca-cert
            - /airlock/ca/ca.crt
            - --mitm-ca-key
            - /airlock/ca-private/ca.key
          env:
            - name: GITHUB_BASIC_AUTH
              valueFrom:
                secretKeyRef:
                  name: airlock-github-basic-auth
                  key: GITHUB_BASIC_AUTH
          ports:
            - name: grpc
              containerPort: 50051
          volumeMounts:
            - name: policy
              mountPath: /airlock/policy
              readOnly: true
            - name: mitm-ca-public
              mountPath: /airlock/ca
              readOnly: true
            - name: mitm-ca-private
              mountPath: /airlock/ca-private
              readOnly: true
      volumes:
        - name: policy
          configMap:
            name: airlock-github-policy
        - name: envoy-config
          configMap:
            name: airlock-github-envoy
        - name: mitm-ca-public
          secret:
            secretName: airlock-github-ca-public
        - name: mitm-ca-private
          secret:
            secretName: airlock-github-ca-private
EOF

kubectl apply -f "$tmpdir/workload.yaml" >/dev/null
kubectl rollout status deployment/"$APP_NAME" -n "$NAMESPACE" --timeout=180s
smoke_pod="$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name="$APP_NAME" --sort-by=.metadata.creationTimestamp --no-headers | awk 'END { print $1 }')"

kubectl exec -n "$NAMESPACE" "$smoke_pod" -c app -- sh -c '
  ! env | grep -Eq "^(GITHUB_PAT|GITHUB_BASIC_AUTH)=" &&
  test ! -e /airlock/ca-private/ca.key &&
  test ! -e /airlock/policy/policy.yaml
' || {
  echo "app container unexpectedly has GitHub credentials, private CA key, or proxy policy mounted" >&2
  exit 1
}

if kubectl exec -n "$NAMESPACE" "$smoke_pod" -c app -- \
  sh -c "rm -rf /tmp/portfolio-direct && git \
    -c http.proxy= \
    -c https.proxy= \
    -c credential.helper= \
    clone --depth 1 https://${GITHUB_HOST}/${GITHUB_REPO}.git /tmp/portfolio-direct >/tmp/git-direct.log 2>&1"; then
  echo "direct GitHub clone unexpectedly succeeded without proxy-injected credentials" >&2
  kubectl exec -n "$NAMESPACE" "$smoke_pod" -c app -- cat /tmp/git-direct.log >&2 || true
  exit 1
fi

kubectl exec -n "$NAMESPACE" "$smoke_pod" -c app -- \
  sh -c "rm -rf /tmp/portfolio && git \
    -c http.proxy=http://127.0.0.1:10000 \
    -c http.sslCAInfo=/airlock/ca/ca.crt \
    -c credential.helper= \
    clone --depth 1 https://${GITHUB_HOST}/${GITHUB_REPO}.git /tmp/portfolio >/tmp/git-clone.log 2>&1 && test -d /tmp/portfolio/.git" || {
  echo "GitHub private repository clone failed" >&2
  kubectl exec -n "$NAMESPACE" "$smoke_pod" -c app -- cat /tmp/git-clone.log >&2 || true
  kubectl logs -n "$NAMESPACE" "$smoke_pod" -c envoy --tail=160 >&2 || true
  kubectl logs -n "$NAMESPACE" "$smoke_pod" -c proxy-worker --tail=160 >&2 || true
  exit 1
}

if kubectl exec -n "$NAMESPACE" "$smoke_pod" -c app -- \
  sh -c 'for value in "$@"; do grep -F "$value" /tmp/git-clone.log /tmp/git-direct.log 2>/dev/null && exit 0; done; exit 1' \
    sh "$GITHUB_PAT" "$(cat "$tmpdir/github-basic-auth")"; then
  echo "app git logs leaked GitHub credentials" >&2
  exit 1
fi

if kubectl exec -n "$NAMESPACE" "$smoke_pod" -c app -- \
  git -c http.proxy=http://127.0.0.1:10000 \
    -c http.sslCAInfo=/airlock/ca/ca.crt \
    -c credential.helper= \
    ls-remote https://denied.example.test/not/allowed.git >/dev/null 2>&1; then
  echo "denied GitHub CONNECT request unexpectedly succeeded" >&2
  exit 1
fi

proxy_logs="$(kubectl logs -n "$NAMESPACE" "$smoke_pod" -c proxy-worker --tail=1000)"
case "$proxy_logs" in
  *"allowed ext_proc CONNECT"*"destination=${GITHUB_HOST}:443"*) ;;
  *) echo "proxy-worker logs did not record the allowed GitHub CONNECT request" >&2; echo "$proxy_logs" >&2; exit 1 ;;
esac
case "$proxy_logs" in
  *"sds stream resources=${GITHUB_HOST}"*|*"sds fetch resources=${GITHUB_HOST}"*) ;;
  *) echo "proxy-worker logs did not record an SDS request for ${GITHUB_HOST}" >&2; echo "$proxy_logs" >&2; exit 1 ;;
esac
case "$proxy_logs" in
  *"allowed ext_proc request"*"destination=${GITHUB_HOST}:443"*"Authorization Value:Basic [REDACTED]"*) ;;
  *) echo "proxy-worker logs did not record redacted GitHub Authorization injection" >&2; echo "$proxy_logs" >&2; exit 1 ;;
esac
case "$proxy_logs" in
  *"$GITHUB_PAT"*|*"$(cat "$tmpdir/github-basic-auth")"*) echo "proxy-worker logs leaked GitHub credentials" >&2; exit 1 ;;
esac

echo "github CONNECT SDS smoke passed"
