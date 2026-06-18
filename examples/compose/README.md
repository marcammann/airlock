# Docker Compose Examples

Runnable Docker Compose scenarios live here. These examples are intended for
local workflow testing without a Kubernetes cluster.

- `standalone`: no control plane, builtin HTTP proxy, with `opencode` and
  `codex` profiles.
- `control-plane-enrollment`: control plane plus API-key enrollment, builtin
  HTTP proxy, one allowed curl and one denied curl.
- `spiffe-envoy`: SPIRE/SPIFFE control-plane auth, Envoy ext_proc data path,
  one allowed curl and one denied curl.
