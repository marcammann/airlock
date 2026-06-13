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

- `policy:list`
- `policy:read`
- `policy:write`
- `policy:delete`
- `policy:approve`
- `providers:read`
- `providers:write`
- `users:manage`
- `roles:manage`
- `audit:read`

Phase one grants only `policy:list` and `policy:read`.

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

## Policy Ownership

Policies include a source marker:

- `crd`: managed through Kubernetes CRDs, read-only in the UI.
- `file`: loaded from static files, read-only in the UI.
- `database`: future mutable control-plane backend.

The UI should never silently edit CRD or file-managed resources. If write
support lands later, database-managed policies should be the first editable
surface.

## Admin API

Start with:

```text
GET /v1/admin/policies
GET /v1/admin/proxies
```

Later:

```text
GET /v1/admin/policies/{namespace}/{name}
GET /v1/admin/secret-provider-configs
GET /v1/admin/audit-events
GET /v1/admin/audit/egress-decisions
POST /v1/admin/policies
PATCH /v1/admin/policies/{namespace}/{name}
DELETE /v1/admin/policies/{namespace}/{name}
```

The admin API is separate from the worker policy API. Worker SPIFFE auth should
not become user/admin auth.

## Security Requirements

- Secure, HTTP-only session cookies.
- CSRF protection for mutations.
- Strict CSP and no inline secrets.
- Control-plane credentials only in server-side runtime env.
- No secret values in API responses.
- Redact rewrite templates and secret refs unless a permission explicitly
  allows viewing metadata.
- Structured audit logs for every admin request.
- Structured proxy egress decision logs for allowed, denied, and dependency
  failed requests.
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
