# Airlock WebUI

The Airlock WebUI is a Next.js admin console for viewing and managing Airlock
control-plane state.

This first cut is read-only and shows loaded Airlock policies from:

```text
GET /v1/admin/policies
```

## Local Development

Start a control plane with at least one policy, then run:

```sh
AIRLOCK_CONTROL_PLANE_URL=http://127.0.0.1:8080 npm run dev
```

If the control plane uses `--auth-mode dev-token`, pass:

```sh
AIRLOCK_CONTROL_PLANE_TOKEN=...
```

## Configuration

```env
AIRLOCK_CONTROL_PLANE_URL=http://airlock-control-plane:8080
AIRLOCK_CONTROL_PLANE_TOKEN=
AIRLOCK_WEB_AUTH_MODE=dev
OIDC_ISSUER=
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=
OIDC_REDIRECT_URI=
RBAC_GROUP_CLAIM=groups
```

`AIRLOCK_CONTROL_PLANE_TOKEN` is server-side only. It must not be exposed to
browser JavaScript.

## Production Direction

- OIDC/OAuth login owns identity, MFA, and sign-up policy.
- Airlock RBAC maps OIDC claims to Airlock roles.
- Browser clients talk only to the WebUI.
- WebUI talks to the control plane using a trusted internal identity.
- CRD-managed policies stay read-only in the UI.
