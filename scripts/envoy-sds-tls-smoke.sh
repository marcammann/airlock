#!/usr/bin/env sh
set -eu

NAMESPACE="${NAMESPACE:-demo}"
APP_NAME="${APP_NAME:-airlock-envoy-sds-smoke}"
PROXY_IMAGE="${PROXY_WORKER_IMAGE:-airlock-proxy-worker:dev}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.31.0}"
UPSTREAM_DNS="tls-sds-upstream.${NAMESPACE}.svc.cluster.local"
TOKEN_VALUE="${TOKEN_VALUE:-envoy-sds-smoke-token}"
OPENSSL="${OPENSSL:-openssl}"
RUN_ID="$(date +%s)"

if ! command -v "$OPENSSL" >/dev/null 2>&1; then
  if [ -x /opt/homebrew/bin/openssl ]; then
    OPENSSL=/opt/homebrew/bin/openssl
  fi
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/airlock-envoy-sds-smoke.XXXXXX")"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

umask 077

"$OPENSSL" req -x509 -newkey rsa:2048 -nodes \
  -keyout "$tmpdir/ca.key" \
  -out "$tmpdir/ca.crt" \
  -days 1 \
  -subj "/CN=airlock envoy sds smoke ca" >/dev/null 2>&1

"$OPENSSL" req -newkey rsa:2048 -nodes \
  -keyout "$tmpdir/upstream.key" \
  -out "$tmpdir/upstream.csr" \
  -subj "/CN=${UPSTREAM_DNS}" >/dev/null 2>&1

cat >"$tmpdir/upstream.ext" <<EOF
subjectAltName=DNS:${UPSTREAM_DNS}
extendedKeyUsage=serverAuth
EOF

"$OPENSSL" x509 -req \
  -in "$tmpdir/upstream.csr" \
  -CA "$tmpdir/ca.crt" \
  -CAkey "$tmpdir/ca.key" \
  -CAcreateserial \
  -out "$tmpdir/upstream.crt" \
  -days 1 \
  -sha256 \
  -extfile "$tmpdir/upstream.ext" >/dev/null 2>&1

cat >"$tmpdir/policy.yaml" <<EOF
apiVersion: airlock.dev/v1alpha1
kind: AirlockPolicy
metadata:
  name: envoy-sds-smoke
spec:
  workload:
    spiffeId: spiffe://airlock.local/ns/${NAMESPACE}/sa/${APP_NAME}/component/airlock-proxy-worker
    namespace: ${NAMESPACE}
    serviceAccount: ${APP_NAME}
  egress:
    - name: tls-sds-upstream
      scheme: https
      host: ${UPSTREAM_DNS}
      port: 8443
      rewrites:
        - target: header
          name: Authorization
          valueTemplate: "Bearer {{secret}}"
          valueFrom:
            provider: env
            name: envoy-sds-smoke-token
            env: AIRLOCK_TEST_TOKEN
EOF

cat >"$tmpdir/envoy.yaml" <<EOF
node:
  id: ${APP_NAME}
  cluster: airlock
static_resources:
  listeners:
    - name: airlock_tls_egress
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 10443
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: ${UPSTREAM_DNS}
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
                stat_prefix: airlock_tls_egress
                route_config:
                  name: airlock_tls_egress_route
                  virtual_hosts:
                    - name: demo
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: tls_sds_upstream
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
    - name: tls_sds_upstream
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      connect_timeout: 1s
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: ${UPSTREAM_DNS}
          common_tls_context:
            validation_context:
              trusted_ca:
                filename: /airlock/ca/ca.crt
      load_assignment:
        cluster_name: tls_sds_upstream
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: ${UPSTREAM_DNS}
                      port_value: 8443
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
EOF

kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE" >/dev/null

kubectl -n "$NAMESPACE" create secret generic airlock-envoy-sds-ca-public \
  --from-file=ca.crt="$tmpdir/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create secret generic airlock-envoy-sds-ca-private \
  --from-file=ca.key="$tmpdir/ca.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create secret generic airlock-envoy-sds-upstream \
  --from-file=tls.crt="$tmpdir/upstream.crt" \
  --from-file=tls.key="$tmpdir/upstream.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create configmap airlock-envoy-sds-policy \
  --from-file=policy.yaml="$tmpdir/policy.yaml" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create configmap airlock-envoy-sds-config \
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
          image: curlimages/curl:8.10.1
          command:
            - sleep
            - infinity
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
            - name: envoy-https
              containerPort: 10443
          volumeMounts:
            - name: envoy-config
              mountPath: /etc/envoy
              readOnly: true
            - name: mitm-ca-public
              mountPath: /airlock/ca
              readOnly: true
        - name: upstream
          image: registry.k8s.io/e2e-test-images/agnhost:2.45
          args:
            - netexec
            - --http-port=8443
            - --udp-port=-1
            - --tls-cert-file=/airlock/upstream/tls.crt
            - --tls-private-key-file=/airlock/upstream/tls.key
          ports:
            - name: https
              containerPort: 8443
          readinessProbe:
            tcpSocket:
              port: https
            initialDelaySeconds: 2
            periodSeconds: 5
          volumeMounts:
            - name: upstream-tls
              mountPath: /airlock/upstream
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
            - name: AIRLOCK_TEST_TOKEN
              value: ${TOKEN_VALUE}
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
            name: airlock-envoy-sds-policy
        - name: envoy-config
          configMap:
            name: airlock-envoy-sds-config
        - name: mitm-ca-public
          secret:
            secretName: airlock-envoy-sds-ca-public
        - name: mitm-ca-private
          secret:
            secretName: airlock-envoy-sds-ca-private
        - name: upstream-tls
          secret:
            secretName: airlock-envoy-sds-upstream
---
apiVersion: v1
kind: Service
metadata:
  name: tls-sds-upstream
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: ${APP_NAME}
    app.kubernetes.io/part-of: airlock
spec:
  selector:
    app.kubernetes.io/name: ${APP_NAME}
  ports:
    - name: https
      port: 8443
      targetPort: https
EOF

kubectl apply -f "$tmpdir/workload.yaml" >/dev/null
kubectl rollout status deployment/"$APP_NAME" -n "$NAMESPACE" --timeout=180s
smoke_pod="$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name="$APP_NAME" --sort-by=.metadata.creationTimestamp --no-headers | awk 'END { print $1 }')"

allowed_body=""
for attempt in $(seq 1 30); do
  if allowed_body="$(kubectl exec -n "$NAMESPACE" "$smoke_pod" -c app -- \
    curl -fsS --max-time 10 \
      --connect-to "${UPSTREAM_DNS}:8443:127.0.0.1:10443" \
      --cacert /airlock/ca/ca.crt \
      "https://${UPSTREAM_DNS}:8443/header?key=Authorization" 2>"$tmpdir/allowed.err")"; then
    break
  fi
  sleep 1
done

if ! printf "%s" "$allowed_body" | grep -q "Bearer ${TOKEN_VALUE}"; then
  echo "Envoy SDS TLS request did not reach upstream with rewritten Authorization header" >&2
  cat "$tmpdir/allowed.err" >&2 || true
  kubectl logs -n "$NAMESPACE" "$smoke_pod" -c envoy --tail=120 >&2 || true
  kubectl logs -n "$NAMESPACE" "$smoke_pod" -c proxy-worker --tail=120 >&2 || true
  exit 1
fi

if kubectl exec -n "$NAMESPACE" "$smoke_pod" -c app -- \
  curl -kfsS --max-time 10 \
    --connect-to "denied.example.test:8443:127.0.0.1:10443" \
    "https://denied.example.test:8443/header?key=Authorization" >/dev/null 2>&1; then
  echo "denied Envoy SDS HTTPS request unexpectedly succeeded" >&2
  exit 1
fi

proxy_logs="$(kubectl logs -n "$NAMESPACE" "$smoke_pod" -c proxy-worker --tail=1000)"
case "$proxy_logs" in
  *"sds stream resources=${UPSTREAM_DNS}"*|*"sds fetch resources=${UPSTREAM_DNS}"*) ;;
  *)
  echo "proxy-worker logs did not record an SDS request for ${UPSTREAM_DNS}" >&2
  echo "$proxy_logs" >&2
  exit 1
  ;;
esac
case "$proxy_logs" in
  *"allowed ext_proc request"*) ;;
  *) echo "proxy-worker logs did not record the allowed decrypted HTTPS request" >&2; exit 1 ;;
esac
case "$proxy_logs" in
  *"denied ext_proc request"*) ;;
  *) echo "proxy-worker logs did not record the denied decrypted HTTPS request" >&2; exit 1 ;;
esac
case "$proxy_logs" in
  *"$TOKEN_VALUE"*) echo "proxy-worker logs leaked the injected token" >&2; exit 1 ;;
esac

echo "envoy SDS TLS smoke passed"
