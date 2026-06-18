# Daytona Examples

These examples show how Airlock can be embedded into Daytona-style sandboxes.

- `soft-sandbox`: a single custom sandbox image that runs the Airlock proxy
  worker and the workspace process as separate Unix users. It uses a local
  policy and a root-only secret file copied into an Airlock-only location at
  startup.

