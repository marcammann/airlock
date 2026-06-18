# Airlock WebUI Production Plan

## Goal

Build `airlock-web` as a separate admin console service for Airlock operators.
The first production path is read-only policy visibility. Mutations come later
behind explicit RBAC, audit, and source-of-truth rules.

## Architecture

```text
Browser
  -> airlock-web (Next.js)
  -> OIDC/OAuth provider
  -> airlock-web server-side BFF
  -> airlock-control-plane admin API
```

The browser never receives control-plane credentials. The WebUI is the policy
enforcement point for user sessions and RBAC. The control plane remains the
authority for policy state.

The built-in near-term model is a self-managed BFF:

```text
Browser
  -> WebUI OIDC login/session
  -> WebUI RBAC
  -> control plane with WebUI service token
```

This closes the browser-facing auth boundary without requiring an additional
identity broker. The WebUI must treat every `/api/*` route and every
server-rendered admin page as privileged because both can use the server-side
control-plane token.

The preferred future production model is broker-issued user tokens:

```text
Browser
  -> WebUI session
  -> identity broker access token with aud=airlock-control-plane
  -> control plane validates issuer/audience and applies RBAC to the user
```

Examples of the broker are Keycloak, Zitadel, Auth0, Okta, or Dex. In that
model the control plane should trust the broker issuer, not raw social-provider
tokens, and WebUI should forward the user's Airlock-scoped access token instead
of using a shared admin service token.

## Auth

Production auth should use generic OIDC/OAuth. Supported provider profiles:

- Generic OIDC
- Okta
- Auth0
- Microsoft Entra ID
- Google or GitHub for small teams and demos

Sign-up modes:

- `disabled`: only existing IdP users/groups can access Airlock.
- `invite-only`: invited users can complete first sign-in.
- `domain-allowlist`: users from configured email domains can sign in.
- `first-user-bootstrap`: creates the first owner only when explicitly enabled.

Avoid password auth in Airlock. The IdP should own MFA, recovery, lifecycle, and
device/session policy.

## RBAC

Initial roles:

- `owner`: full administrative control.
- `admin`: configure Airlock resources and manage users.
- `operator`: operate policies and providers without user management.
- `viewer`: read-only access to policies and providers.
- `auditor`: read-only access to policies, status, and audit logs.

Initial permissions:

- `workload:list`
- `workload:read`
- `policy:write`
- `policy:delete`
- `policy:approve`
- `providers:read`
- `providers:write`
- `users:manage`
- `roles:manage`
- `audit:read`

The initial read-only console grants only `workload:list` and `workload:read`.

OIDC claims map to Airlock roles:

```yaml
rbac:
  mappings:
    - claim: groups
      value: airlock-admins
      role: admin
    - claim: groups
      value: airlock-viewers
      role: viewer
```

## Workload And Policy Ownership

The UI primary surface is the compiled workload view. `AirlockWorkload`
resources assign one or more reusable `AirlockPolicy` objects, and the control
plane serves one effective policy per workload to proxy workers.

Workloads and policies include a source marker:

- `crd`: managed through Kubernetes CRDs, read-only in the UI.
- `file`: loaded from static files, read-only in the UI.
- `database`: future mutable control-plane backend.

The UI should never silently edit CRD or file-managed resources. If write
support lands later, database-managed workloads and policies should be the first
editable surface.

## Admin API

Start with:

```text
GET /v1/admin/workloads
GET /v1/admin/proxies
```

Later:

```text
GET /v1/admin/workloads/{namespace}/{name}
GET /v1/admin/policies
GET /v1/admin/secret-provider-configs
GET /v1/admin/audit-events
GET /v1/admin/events
POST /v1/admin/workloads
PATCH /v1/admin/workloads/{namespace}/{name}
DELETE /v1/admin/workloads/{namespace}/{name}
```

The admin API is separate from the worker policy API. Worker SPIFFE auth should
not become user/admin auth.

The control plane supports separate auth planes. In the current self-managed
WebUI model, an admin provider in `auth.yaml` authenticates the WebUI service
token. In the preferred broker model, `--admin-auth=oidc` authenticates the
actual user access token forwarded by the WebUI:

```text
--worker-auth=spiffe
--admin-listen=:8081
--admin-auth=oidc
--admin-oidc-issuer=https://issuer.example
--admin-oidc-audience=airlock-web
--admin-rbac-binding=airlock-viewers=viewer
```

Worker endpoints stay on the worker listener and use SPIFFE mTLS. Admin
endpoints can be exposed on a separate listener behind ingress/API gateway TLS
and validate OIDC bearer tokens directly.

## Security Requirements

- Secure, HTTP-only session cookies.
- CSRF protection for mutations.
- Strict CSP and no inline secrets.
- Control-plane admin bearer tokens only in server-side runtime env.
- No secret values in API responses.
- Redact rewrite templates and secret refs unless a permission explicitly
  allows viewing metadata.
- Structured audit logs for every admin request.
- Structured proxy egress decision logs for allowed, denied, and proxy error
  requests.
- Request IDs propagated from WebUI to control plane.
- Rate limits on admin API routes.
- OIDC group and role changes reflected on session refresh.

## Proxy Status and Egress Audit

The control plane should be the source of truth for current proxy inventory:
active proxies, last heartbeat, and last policy fetch. Proxies should emit
heartbeats to the control plane with a short TTL.

OTEL should carry request decision history from the proxy workers. The WebUI can
surface recent allow/deny decisions by querying a stable Airlock admin API that
is backed by the configured OTEL log destination. This keeps liveness separate
from historical audit evidence.

## Delivery Sequence

1. Read-only policy list.
2. OIDC login and dev login mode.
3. RBAC middleware and route-level permission checks.
4. Policy detail page with safe redaction.
5. Proxy status page backed by proxy heartbeats.
6. Secret provider config list.
7. Audit log view, including proxy allow/deny decisions.
8. Database-backed mutable policy store.
9. Policy create/edit with review and approval.
10. K8s deployment manifests and Helm values.
11. End-to-end Playwright coverage.
