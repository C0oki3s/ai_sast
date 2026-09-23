# Code Scanning worker image

The image runs the Code Scanning migration and worker commands as UID/GID
`10001`, with no shell entrypoint and no embedded credentials. The example
Compose file makes the root filesystem read-only, removes Linux capabilities,
enables `no-new-privileges`, mounts source snapshots read-only, and places the
worker on an internal network.

The `postgres` and `litellm` services must join the same `scanner_backend`
network. Only the LiteLLM gateway receives controlled provider/research egress;
the worker itself has no default Internet route. In Kubernetes or ECS, enforce
the same boundary with NetworkPolicy or security-group rules rather than
relying on the Compose example.

Create the signed asset bundle before starting the worker and inject secrets
through the platform secret store. See `docs/CODE_SCANNING_OPERATIONS.md`.
