# Airlock Auth Config

`airlock-control-plane` can load admin and enrollment auth from YAML:

```sh
airlock-control-plane \
  --auth-config /etc/airlock/auth.yaml \
  --admin-listen :8081
```

Worker auth remains separate and explicit through `--worker-auth`.

A runnable local example lives in `examples/compose/control-plane-enrollment`.

## Example

```yaml
version: airlock.dev/v1alpha1
auth:
  admin:
    providers:
      - name: console-local
        type: apiKey
        keys:
          - id: console
            env: AIRLOCK_CONSOLE_API_KEY
    rbac:
      roleBindings:
        - subject: key:console
          roles: [viewer]
      roles:
        viewer:
          permissions:
            - policy:read
            - workload:read
            - proxy:read
            - audit:read

  enrollment:
    defaultTTL: 2m
    maxTTL: 10m
    providers:
      - name: daytona-dispatchers
        type: apiKey
        keys:
          - id: local-daytona
            env: AIRLOCK_DAYTONA_DISPATCHER_API_KEY
      - name: github-actions
        type: oidc
        issuer: https://token.actions.githubusercontent.com
        audience: airlock-control-plane
        requiredClaims:
          repository: marcammann/airlock
          ref: refs/heads/main
    grants:
      - subject: key:local-daytona
        permissions: [enrollment:create]
        workloads:
          - namespace: daytona-dev
            name: soft-sandbox-openai
      - subject: provider:github-actions:sub:repo:marcammann/airlock:ref:refs/heads/main
        permissions: [enrollment:create]
        workloads:
          - namespace: daytona-prod
            name: soft-sandbox-openai
```

API key entries can use `hash`, `value`, `env`, or `file`. Production configs
should prefer `hash: sha256:<hex>` or `file`.

Enrollment tokens are short-lived and one-time-use. A dispatcher creates one on
the regular control-plane listener, protected by enrollment auth:

```http
POST /v1/enrollments
Authorization: Bearer <dispatcher credential>
Content-Type: application/json

{
  "workload": {
    "namespace": "daytona-dev",
    "name": "soft-sandbox-openai"
  },
  "ttlSeconds": 120
}
```

The Airlock process redeems it:

```http
POST /v1/enrollments/redeem
Authorization: Bearer <enrollment token>
```

The response contains the compiled worker policy.
