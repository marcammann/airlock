#!/usr/bin/env sh
set -eu

NAMESPACE="${NAMESPACE:-demo}"
APP_NAME="${APP_NAME:-airlock-tls-smoke}"
PROXY_IMAGE="${PROXY_WORKER_IMAGE:-airlock-proxy-worker:dev}"
UPSTREAM_DNS="tls-upstream.${NAMESPACE}.svc.cluster.local"
TOKEN_VALUE="${TOKEN_VALUE:-tls-smoke-token}"
OPENSSL="${OPENSSL:-openssl}"

if ! command -v "$OPENSSL" >/dev/null 2>&1; then
  if [ -x /opt/homebrew/bin/openssl ]; then
    OPENSSL=/opt/homebrew/bin/openssl
  fi
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/airlock-tls-smoke.XXXXXX")"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

umask 077

"$OPENSSL" req -x509 -newkey rsa:2048 -nodes \
  -keyout "$tmpdir/ca.key" \
  -out "$tmpdir/ca.crt" \
  -days 1 \
  -sha256 \
  -subj "/CN=airlock tls smoke ca" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1

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
  name: tls-smoke
spec:
  workload:
    spiffeId: spiffe://airlock.local/ns/${NAMESPACE}/sa/${APP_NAME}/component/airlock-proxy-worker
    namespace: ${NAMESPACE}
    serviceAccount: ${APP_NAME}
  egress:
    - name: tls-upstream
      scheme: https
      host: ${UPSTREAM_DNS}
      port: 8443
      rewrites:
        - target: header
          name: Authorization
          valueTemplate: "Bearer {{secret}}"
          valueFrom:
            provider: env
            name: tls-smoke-token
            env: AIRLOCK_TEST_TOKEN
EOF

kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE" >/dev/null

kubectl -n "$NAMESPACE" create secret generic airlock-tls-smoke-ca-public \
  --from-file=ca.crt="$tmpdir/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create secret generic airlock-tls-smoke-ca-private \
  --from-file=ca.key="$tmpdir/ca.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create secret generic airlock-tls-smoke-upstream \
  --from-file=tls.crt="$tmpdir/upstream.crt" \
  --from-file=tls.key="$tmpdir/upstream.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl -n "$NAMESPACE" create configmap airlock-tls-smoke-policy \
  --from-file=policy.yaml="$tmpdir/policy.yaml" \
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
            - http:builtin@127.0.0.1:18080
            - --no-control-plane
            - --policy
            - /airlock/policy/policy.yaml
            - --mitm-ca-cert
            - /airlock/ca/ca.crt
            - --mitm-ca-key
            - /airlock/ca-private/ca.key
            - --upstream-ca-cert
            - /airlock/ca/ca.crt
          env:
            - name: AIRLOCK_TEST_TOKEN
              value: ${TOKEN_VALUE}
          ports:
            - name: proxy
              containerPort: 18080
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
            name: airlock-tls-smoke-policy
        - name: mitm-ca-public
          secret:
            secretName: airlock-tls-smoke-ca-public
        - name: mitm-ca-private
          secret:
            secretName: airlock-tls-smoke-ca-private
        - name: upstream-tls
          secret:
            secretName: airlock-tls-smoke-upstream
---
apiVersion: v1
kind: Service
metadata:
  name: tls-upstream
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

allowed_body="$(kubectl exec -n "$NAMESPACE" deploy/"$APP_NAME" -c app -- \
  curl -fsS --max-time 10 \
    --proxy http://127.0.0.1:18080 \
    --cacert /airlock/ca/ca.crt \
    "https://${UPSTREAM_DNS}:8443/header?key=Authorization")"

if ! printf "%s" "$allowed_body" | grep -q "Bearer ${TOKEN_VALUE}"; then
  echo "TLS request did not reach upstream with rewritten Authorization header" >&2
  echo "$allowed_body" >&2
  exit 1
fi

if kubectl exec -n "$NAMESPACE" deploy/"$APP_NAME" -c app -- \
  curl -fsS --max-time 10 \
    --proxy http://127.0.0.1:18080 \
    --cacert /airlock/ca/ca.crt \
    "https://denied.example.test/header?key=Authorization" >/dev/null 2>&1; then
  echo "denied HTTPS request unexpectedly succeeded" >&2
  exit 1
fi

proxy_logs="$(kubectl logs -n "$NAMESPACE" deploy/"$APP_NAME" -c proxy-worker --tail=1000)"
if ! printf "%s" "$proxy_logs" | grep -q "allowed request"; then
  echo "proxy-worker logs did not record the allowed HTTPS request" >&2
  exit 1
fi
if ! printf "%s" "$proxy_logs" | grep -q "denied CONNECT"; then
  echo "proxy-worker logs did not record the denied HTTPS CONNECT" >&2
  exit 1
fi
if printf "%s" "$proxy_logs" | grep -q "$TOKEN_VALUE"; then
  echo "proxy-worker logs leaked the injected token" >&2
  exit 1
fi

echo "tls termination smoke passed"
