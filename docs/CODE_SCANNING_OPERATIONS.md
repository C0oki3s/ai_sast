# Code Scanning production operations

## Deployment boundary

Run migrations as a one-shot job, then run stateless workers against immutable
snapshot directories. Snapshots are mounted read-only; outputs use a separate
writable volume. A worker never clones repositories, installs target
dependencies, executes target code, or handles SCM webhooks.

The worker accepts only `file://` snapshot and output URIs below its configured
roots. It rejects symbolic links, verifies the snapshot's stored tree hash
before scanning, and invokes the scanner with a fixed argument vector.

## Required configuration

Production mode requires a PostgreSQL URL whose `sslmode` is `require`,
`verify-ca`, or `verify-full`. Prefer `verify-full` with a private CA. Supply:

```dotenv
PLAIDNOX_PRODUCTION_MODE=true
PLAIDNOX_DATABASE_URL=postgresql+psycopg://.../code_scanning?sslmode=verify-full
LITELLM_API_BASE=https://litellm.internal
LITELLM_API_KEY=<virtual key with gateway-side budget>
PLAIDNOX_SNAPSHOT_ROOT=/var/lib/plaidnox/snapshots
PLAIDNOX_OUTPUT_ROOT=/var/lib/plaidnox/output
PLAIDNOX_WORKER_ID=<stable replica identity>
PLAIDNOX_REQUIRE_SIGNED_ASSETS=true
PLAIDNOX_ASSET_BUNDLE_PATH=/run/config/plaidnox-assets.json
PLAIDNOX_ASSET_BUNDLE_SIGNING_KEY=<secret-manager value>
```

`*_FILE` variants are supported for protected values in the deployment
example. Keep the LiteLLM gateway and PostgreSQL on a private network. Permit
the worker to reach only those services, telemetry collectors, and the
Perplexity API. General model-provider egress belongs to LiteLLM; direct
Perplexity egress is restricted to knowledge-routed security research (used only when stored knowledge is exhausted).

## Migrations and signed assets

Apply migrations before rolling workers:

```bash
plaidnox-sast migrate
```

The migration runner records SHA-256 checksums and refuses to accept changed
migration content. Generate a versioned asset manifest in a controlled release
job and deploy the JSON with the matching secret-manager signing key:

```bash
plaidnox-sast create-asset-bundle \
  --bundle-version 2026.09.23.1 \
  --key-id code-scanning-release-2026-09 \
  --validity-days 30 \
  --output plaidnox-assets.json

plaidnox-sast verify-asset-bundle plaidnox-assets.json
```

Workers fail before leasing or scanning when required assets are unsigned,
expired, modified, or signed with the wrong key.

## Queue and recovery

The enqueue command records an idempotency key and immutable snapshot hash:

```bash
plaidnox-sast enqueue-local /snapshots/job-01 \
  --codebase app/payment-api \
  --revision 0123456789abcdef \
  --request-key request-01 \
  --output /outputs/job-01 \
  --tenant-id tenant-01
```

Workers use compare-and-set leases and periodic heartbeats. A process that
loses its lease cannot complete the job. Expired leases are reclaimable until
the configured attempt limit; failures record a bounded failure code rather
than source or model content. Graceful termination stops new leases and lets
the active scanner subprocess finish within the platform grace period.

Tenant controls cap concurrent jobs, daily jobs, and monthly model cost.
Application-side call/token/cost limits are additional safety rails; the
LiteLLM virtual-key budget remains the authoritative dollar ceiling.

## Artifacts, retention, deletion, and audit

Store generated reports in an encrypted object or block store. The database
keeps tenant-scoped artifact URI, content hash, encryption-key reference,
expiry, and deletion state. Retention and deletion controllers must use those
records to remove the object first and then mark the row deleted. Customer
deletion requests and audit events are durable and tenant-scoped.

Audit metadata is allowlisted, recursively redacted, and content-hashed. Do
not put source snippets, prompts, model responses, credentials, or raw
provider errors in logs, traces, or audit metadata.

## Observability and alerts

Set `PLAIDNOX_OTEL_ENABLED=true` only in images installed with the
`observability` extra. Export traces and metrics through the platform's normal
OpenTelemetry configuration. Codebase and revision values are hashed before
they become span attributes.

Alert on queue age, exhausted retries, lease loss, incomplete scans, model
budget rejection, LiteLLM error rate, migration checksum failure, asset-bundle
verification failure, deletion backlog, artifact-expiry backlog, and database
capacity. Never attach report or source bodies to alerts.

## Backup and restore

Take encrypted PostgreSQL backups and encrypted artifact-store snapshots with
separate retention. On a disposable environment, restore both, apply pending
migrations, verify migration checksums, reclaim an expired job lease, and
compare artifact hashes. Record recovery time and recovery point results as
release evidence. Do not test restore procedures against the production
database.

## Resuming an interrupted local scan

`scan-local` creates `scan-checkpoint.sqlite` in the output directory unless
`--no-checkpoint` is supplied. Use the same command, source snapshot, revision,
output directory, and checkpoint path after a provider-credit failure, process
crash, or operator interruption.

The journal records every model operation as pending before the request. It
stores the redacted rendered prompts, response schema, selected execution
route, and failure type. A schema-valid response is then marked complete and
stored. On restart, completed calls and completed discovery/review/sweep units
are replayed without provider requests; the first pending operation is retried.
Changing the codebase, revision, source-tree content, project security/business
context, source policy, or prompt-manifest version discards stale units.

The SQLite database and its sidecars are created with owner-only permissions
because they can contain proprietary source context. Treat the output directory
as a sensitive scan artifact. Report metrics expose counts and a redacted
resume cursor (`checkpoint_resume_stage`, `checkpoint_resume_operation`, and
`checkpoint_resume_error_type`), never the stored prompt text.
