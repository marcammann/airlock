# Docker Compose Git Checkout Demo

This demo runs a private GitHub HTTPS checkout through Airlock without exposing
GitHub credentials to the app process.

The default topology uses the builtin proxy with a control plane:

```text
oidc container
  local demo issuer for admin API bearer tokens

control-plane container
  airlock-control-plane
  static policy for github.com:443
  worker API on :8080 with explicit insecure dev-token auth
  admin API on :8081 with OIDC/RBAC auth

git-app container
  airlock user: airlock-proxy-worker builtin HTTP proxy on 127.0.0.1:18080
  appuser user: git clone through http.proxy=http://127.0.0.1:18080
```

The proxy-worker fetches policy from the control plane with a development
bearer token and `--insecure-dev-mode`. The admin API is intentionally separate:
the control plane validates a JWT from the local OIDC demo issuer and maps the
`airlock-viewers` group to the Airlock `viewer` role. The app container runs a
small admin smoke that confirms the viewer token can read policies, can see an
active proxy heartbeat, and an unmapped group is denied.

The GitHub PAT is converted to the HTTPS Basic auth payload at container startup
and written to `/run/airlock/secrets/github-basic-auth`, which is owned by the
`airlock` user and unreadable by `appuser`. The app user receives only the
public MITM CA certificate needed for Git to trust the Airlock CONNECT
interception.

Run:

```sh
export GITHUB_PAT=github_pat_or_classic_pat_with_repo_access
make compose-git-demo
```

There are two additional variants:

```sh
make compose-git-envoy-demo
make compose-git-no-control-plane-demo
```

`compose-git-envoy-demo` splits the data path across four containers:

```text
control-plane -> policy API
oidc          -> local admin token issuer
proxy-worker  -> Airlock ext_proc and SDS
envoy         -> HTTPS CONNECT proxy and TLS termination
git-app       -> unprivileged git clone through http://envoy:10000
```

`compose-git-no-control-plane-demo` keeps the original single app/proxy image
shape, but starts the proxy-worker with `--no-control-plane --policy` and mounts
the local policy file directly.

The target defaults to `marcammann/portfolio`. To use another private repo:

```sh
GITHUB_REPO=owner/private-repo make compose-git-demo
```

If the target repo is public, disable the direct-clone negative check:

```sh
GITHUB_REPO=owner/public-repo EXPECT_DIRECT_CLONE_DENIED=false make compose-git-demo
```

Clean up the Compose volume:

```sh
make compose-git-clean
```

What the demo checks:

- `git` runs as `appuser`.
- `airlock-proxy-worker` runs as `airlock`.
- `appuser` cannot read the GitHub credential file.
- `appuser` cannot read the Airlock MITM CA private key.
- The control plane splits worker auth from admin auth.
- The admin API accepts an OIDC/RBAC viewer token.
- The admin API shows an active proxy heartbeat for the worker.
- The admin API rejects an OIDC token with an unmapped group.
- A direct clone without proxy-injected credentials fails for a private repo.
- The proxied clone succeeds through Airlock.
- The no-control-plane variant works from a local mounted policy.
- The Envoy variant runs Git through Envoy CONNECT, while Airlock handles
  ext_proc decisions and SDS certificates.

This is a local Compose demo, so it is not a hard process isolation boundary in
the same way as a Kubernetes sidecar profile with policy-controlled mounts and
networking. It is meant to prove the copy-binary-into-image workflow and the
least-exposed Git credential path for a single image.
