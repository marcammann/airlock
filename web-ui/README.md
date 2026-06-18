# Airlock WebUI

The Airlock WebUI is a Next.js admin console for viewing and managing Airlock
control-plane state.

This first cut is read-only and shows loaded Airlock workloads and proxy status
from:

```text
GET /v1/admin/workloads
GET /v1/admin/proxies
```

Routes:

- `/`: workload inventory
- `/workloads/[workloadKey]`: workload detail and allowed egress
- `/proxies`: proxy inventory
- `/proxies/[proxyKey]`: proxy status and rolling allow/deny counters

## Local Development

Start a control plane with an admin listener and at least one policy:

```sh
cd ../control-plane
go run ./cmd/airlock-control-plane \
  --listen 127.0.0.1:18088 \
  --admin-listen 127.0.0.1:18089 \
  --insecure \
  --admin-auth oidc \
  --admin-oidc-issuer https://issuer.example.test \
  --admin-oidc-audience airlock-web \
  --admin-rbac-binding airlock-viewers=viewer \
  --policy ../fixtures/policies/valid.yaml \
  --workload ../fixtures/workloads/code-agent.yaml
```

Then run the WebUI against the admin listener. For production-like use, the
WebUI requires its own OIDC login and an HTTP-only WebUI session before it will
use the server-side control-plane token:

```sh
AIRLOCK_CONTROL_PLANE_URL=http://127.0.0.1:18089 \
AIRLOCK_CONTROL_PLANE_TOKEN="$OIDC_ACCESS_TOKEN" \
AIRLOCK_WEB_AUTH_MODE=oidc \
AIRLOCK_WEB_SESSION_SECRET="$(openssl rand -base64 32)" \
AIRLOCK_WEB_OIDC_ISSUER=https://issuer.example.test \
AIRLOCK_WEB_OIDC_CLIENT_ID=airlock-web \
AIRLOCK_WEB_OIDC_CLIENT_SECRET=... \
AIRLOCK_WEB_ALLOWED_DOMAINS=example.test \
npm run dev
```

For local-only development without an OIDC provider, start the control plane
with `--insecure`, then run:

```sh
AIRLOCK_CONTROL_PLANE_URL=http://127.0.0.1:18089 \
AIRLOCK_CONTROL_PLANE_TOKEN= \
AIRLOCK_WEB_AUTH_MODE=dev \
AIRLOCK_WEB_DEV_ROLES=admin \
npm run dev
```

If you run the production build over plain HTTP for a local demo, also set
`AIRLOCK_WEB_COOKIE_SECURE=false` so the browser will send the session cookie.

## Configuration

```env
AIRLOCK_CONTROL_PLANE_URL=http://airlock-control-plane:8081
AIRLOCK_CONTROL_PLANE_TOKEN=dev
AIRLOCK_WEB_AUTH_MODE=oidc
AIRLOCK_WEB_SESSION_SECRET=
AIRLOCK_WEB_COOKIE_SECURE=
AIRLOCK_WEB_OIDC_ISSUER=
AIRLOCK_WEB_OIDC_CLIENT_ID=
AIRLOCK_WEB_OIDC_CLIENT_SECRET=
AIRLOCK_WEB_OIDC_REDIRECT_URI=
AIRLOCK_WEB_OIDC_SCOPES=openid email profile
AIRLOCK_WEB_RBAC_GROUPS_CLAIM=groups
AIRLOCK_WEB_RBAC_ROLES_CLAIM=roles
AIRLOCK_WEB_ADMIN_GROUPS=
AIRLOCK_WEB_VIEWER_GROUPS=
AIRLOCK_WEB_ADMIN_EMAILS=
AIRLOCK_WEB_VIEWER_EMAILS=
AIRLOCK_WEB_ALLOWED_DOMAINS=
```

`AIRLOCK_CONTROL_PLANE_TOKEN` is server-side only. Browser users authenticate to
the WebUI first; WebUI API routes and server-rendered pages check the signed
WebUI session plus WebUI RBAC before calling the control plane with that service
token. The token must not be exposed to browser JavaScript.

`AIRLOCK_WEB_AUTH_MODE=dev` is only for local demos. It creates a local signed
session without an external OIDC provider and should be paired with explicit
control-plane `--insecure`.

## Production Direction

- Current built-in model: OIDC login owns browser identity, MFA, and sign-up
  policy; WebUI RBAC maps OIDC claims to WebUI roles; WebUI talks to the control
  plane using a trusted internal service token.
- Preferred future model: use an identity broker such as Keycloak, Zitadel,
  Auth0, Okta, or Dex to mint Airlock control-plane audience tokens. The WebUI
  forwards the user's broker-issued access token and the control plane enforces
  RBAC on the actual user principal.
- CRD-managed workloads and policies stay read-only in the UI.
