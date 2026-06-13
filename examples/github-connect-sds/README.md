# GitHub HTTPS Clone Through Envoy CONNECT SDS

This example validates the explicit proxy path with a private GitHub repository:

1. the app container runs `git clone https://github.com/marcammann/portfolio.git`
2. Git is configured with `http.proxy=http://127.0.0.1:10000`
3. Envoy accepts the HTTPS `CONNECT`
4. Envoy terminates the inner TLS stream with an SDS certificate from the proxy worker
5. ext_proc injects `Authorization: Basic <base64(username:PAT)>`
6. Envoy opens a verified TLS connection to `github.com`

The app container never receives the PAT. The smoke script converts
`GITHUB_BASIC_USER:GITHUB_PAT` to the Basic auth payload and stores it in a
Kubernetes Secret that is exposed only to the `proxy-worker` container.
`GITHUB_BASIC_USER` defaults to `x-access-token`.

The smoke also proves the negative path: the app container has no GitHub
credential environment variables, does not mount the proxy policy or private CA
key, and a direct clone without the proxy fails before the proxied clone
succeeds.

Run it against the local kind cluster:

```sh
export GITHUB_PAT=github_pat_or_classic_pat_with_repo_access
make github-connect-sds-smoke
```

GitHub documents HTTPS Git authentication as username plus PAT-as-password. If
your token requires the real account name in the Basic username slot, set:

```sh
GITHUB_BASIC_USER=your-github-username make github-connect-sds-smoke
```

The target defaults to `marcammann/portfolio`, but can be pointed at another
repository:

```sh
GITHUB_REPO=owner/private-repo make github-connect-sds-smoke
```
