#!/usr/bin/env sh
set -eu

SPIRE_NAMESPACE="${SPIRE_NAMESPACE:-spire-system}"
VAULT_NAMESPACE="${VAULT_NAMESPACE:-vault}"
VAULT_DEPLOYMENT="${VAULT_DEPLOYMENT:-deploy/vault-dev}"
VAULT_ADDR="${AIRLOCK_VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${AIRLOCK_VAULT_TOKEN:-root}"
VAULT_ROLE="${VAULT_ROLE:-airlock-demo-code-agent}"
VAULT_POLICY="${VAULT_POLICY:-airlock-code-agent}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-airlock/openai/code-agent}"
VAULT_SECRET_VALUE="${VAULT_SECRET_VALUE:-vault-smoke-token}"

bundle_json="$(kubectl exec -n "$SPIRE_NAMESPACE" statefulset/spire-server -c spire-server -- \
  /opt/spire/bin/spire-server bundle show \
    -socketPath /tmp/spire-server/private/api.sock \
    -format spiffe \
    -output json)"

jwt_public_keys="$(printf '%s' "$bundle_json" | jq -r '.jwt_authorities[].public_key')"
if [ -z "$jwt_public_keys" ] || printf '%s\n' "$jwt_public_keys" | grep -qx "null"; then
  echo "SPIRE bundle did not include a JWT authority public key" >&2
  exit 1
fi

jwt_config_json="$(printf '%s' "$bundle_json" | jq --arg role "$VAULT_ROLE" '
  {
    jwt_validation_pubkeys: [
      .jwt_authorities[].public_key
      | "-----BEGIN PUBLIC KEY-----\n" + . + "\n-----END PUBLIC KEY-----\n"
    ],
    default_role: $role
  }
')"

if ! kubectl exec -n "$VAULT_NAMESPACE" "$VAULT_DEPLOYMENT" -- sh -c \
  "VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=$VAULT_TOKEN vault auth list -format=json" | grep -q '"jwt/"'; then
  kubectl exec -n "$VAULT_NAMESPACE" "$VAULT_DEPLOYMENT" -- sh -c \
    "VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=$VAULT_TOKEN vault auth enable jwt"
fi

if ! kubectl exec -n "$VAULT_NAMESPACE" "$VAULT_DEPLOYMENT" -- sh -c \
  "VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=$VAULT_TOKEN vault audit list -format=json" | grep -q '"file/"'; then
  kubectl exec -n "$VAULT_NAMESPACE" "$VAULT_DEPLOYMENT" -- sh -c \
    "VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=$VAULT_TOKEN vault audit enable file file_path=stdout"
fi

printf '%s\n' "$jwt_config_json" | kubectl exec -i -n "$VAULT_NAMESPACE" "$VAULT_DEPLOYMENT" -- sh -c \
  "cat >/tmp/spire-jwt-config.json && VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=$VAULT_TOKEN vault write auth/jwt/config @/tmp/spire-jwt-config.json"

kubectl exec -n "$VAULT_NAMESPACE" "$VAULT_DEPLOYMENT" -- sh -c \
  "VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=$VAULT_TOKEN vault delete auth/jwt/role/$VAULT_ROLE >/dev/null 2>&1 || true; VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=$VAULT_TOKEN vault policy delete $VAULT_POLICY >/dev/null 2>&1 || true"

kubectl exec -n "$VAULT_NAMESPACE" "$VAULT_DEPLOYMENT" -- sh -c \
  "VAULT_ADDR=$VAULT_ADDR VAULT_TOKEN=$VAULT_TOKEN vault kv put secret/$VAULT_SECRET_PATH api_key=$VAULT_SECRET_VALUE"

echo "Vault JWT auth bootstrapped; Airlock policy and role left for control-plane reconciliation"
