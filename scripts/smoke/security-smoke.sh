#!/usr/bin/env sh
set -eu

WORKLOAD_IDENTITY="spiffe://airlock.local/ns/demo/sa/code-agent/component/airlock-proxy-worker"
POLICY_URL="https://airlock-control-plane.airlock-system.svc.cluster.local:8443/v1/policies"
VAULT_SECRET_VALUE="${VAULT_SECRET_VALUE:-vault-smoke-token}"
VAULT_POLICY="${VAULT_POLICY:-airlock-code-agent}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-airlock/openai/code-agent}"
VAULT_DENIED_PATH="${VAULT_DENIED_PATH:-airlock/openai/not-allowed}"

SMOKE_NAME=security-baseline ./scripts/smoke/k8s-egress-smoke.sh

control_plane_pod="$(kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock-control-plane --sort-by=.metadata.creationTimestamp --no-headers | awk 'END { print $1 }')"
code_agent_pod="$(kubectl get pods -n demo -l app.kubernetes.io/name=code-agent --sort-by=.metadata.creationTimestamp --no-headers | awk 'END { print $1 }')"

if kubectl exec -n demo "$code_agent_pod" -c app -- \
  curl -kfsS --get \
    --data-urlencode "workload_identity=$WORKLOAD_IDENTITY" \
    "$POLICY_URL" >/dev/null 2>&1; then
  echo "unauthenticated policy request unexpectedly succeeded" >&2
  exit 1
fi

if kubectl logs -n airlock-system "$control_plane_pod" --tail=1000 | grep -q "$VAULT_SECRET_VALUE"; then
  echo "control-plane logs leaked the Vault secret value" >&2
  exit 1
fi

if kubectl logs -n demo "$code_agent_pod" -c proxy-worker --tail=1000 | grep -q "$VAULT_SECRET_VALUE"; then
  echo "proxy-worker logs leaked the Vault secret value" >&2
  exit 1
fi

kubectl exec -n vault deploy/vault-dev -- sh -c "
  set -eu
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_TOKEN=root
  token=\"\$(vault token create -policy=$VAULT_POLICY -field=token)\"
  value=\"\$(VAULT_TOKEN=\"\$token\" vault kv get -field=api_key secret/$VAULT_SECRET_PATH)\"
  test \"\$value\" = \"$VAULT_SECRET_VALUE\"
"

if kubectl exec -n vault deploy/vault-dev -- sh -c "
  set -eu
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_TOKEN=root
  token=\"\$(vault token create -policy=$VAULT_POLICY -field=token)\"
  VAULT_TOKEN=\"\$token\" vault kv get secret/$VAULT_DENIED_PATH >/dev/null 2>&1
" >/dev/null 2>&1; then
  echo "generated Vault policy unexpectedly read an unreferenced secret" >&2
  exit 1
fi

echo "security smoke passed"
