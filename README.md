# PlaidNox Code Security Agent

PlaidNox Code Security is an AI-required, read-only source-code security
pipeline. Every operational scan builds application context, derives explicit
security obligations for structural source regions, acquires only the missing
context needed to disposition those obligations, merges equivalent candidate
evidence, and runs PlaidNox Deep Hunt before any candidate becomes a finding.

The scanner never installs dependencies, runs builds, executes application
code, invokes repository scripts, or reads tracked secret-file contents.

## Product boundary

This package is the standalone Code Scanning engine. Its supported input is an
immutable local source snapshot with an explicit codebase identity and revision.
SCM orchestration, SCA, secrets, cloud/IaC, licenses, outdated software, DAST,
and IDE plugins are separate workstreams documented in
[`docs/PRODUCT_WORKSTREAMS.md`](docs/PRODUCT_WORKSTREAMS.md).

PR/MR review is implemented in the separate `plaidnox_scm` package in this
repository. The deployable `plaidnox-scm-api` exposes `POST /v1/reviews` for
provider adapters. GitHub webhook verification, installation credentials,
checks, and inline comments remain in `PlaidNox/plaidnox-github-bot`; see
[`docs/GITHUB_BOT_INTEGRATION.md`](docs/GITHUB_BOT_INTEGRATION.md).

## Pipeline

```text
immutable local source snapshot
  -> snapshot-owned policy and security/business context
  -> compact Tree-sitter Security IR with no baked-in vulnerability searches
  -> AI-generated reconnaissance search plan from observed repository structure
  -> bounded rg execution and evidence-backed application context
  -> build/reuse Context Fabric snapshot/overlay
  -> LLM-created hunt tasks from architecture, code, business context, and knowledge
  -> knowledge database reuse / retrieval / Perplexity web-research fallback
  -> one obligation-driven discovery review per structural region
  -> typed Context Broker expansion only when an obligation needs evidence
  -> delta-only bounded continuation when the broker returns new context
  -> canonical candidate/evidence merge and root-cause variant sweeps
  -> optional DataDog SAIST candidate input
  -> deterministic candidate route classification
  -> PlaidNox Deep Hunt: entry point -> forward trace -> falsification -> evidence
  -> finding dependencies -> deduplication -> policy -> JSON/SARIF/Markdown
```

The deep-hunt agent is PlaidNox-owned. It uses strict structured responses and
our own evidence schema; it takes inspiration from attacker-first and
falsification practices without vendoring an external agent implementation.

## Run

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[ai]'

.venv/bin/plaidnox-sast scan-local /immutable/workspace/NSTCTF \
  --codebase C0oki3s/NSTCTF \
  --revision 868c7a2018e9a1e95cd068d251694d5ac9f7a6d3 \
  --env-file /secure/path/.env \
  --output artifacts/nstctf
```

Every operational scan uses the LiteLLM SDK. For the local gateway, configure a
virtual key and base URL; no model-provider key is passed to the Deep Hunt
runtime.

```dotenv
LITELLM_API_KEY=<virtual key>
LITELLM_API_BASE=http://localhost:4000
```

Perplexity Sonar web research uses Perplexity's official SDK and a separately
scoped direct credential:

```dotenv
IFRIT_RESEARCH_PROVIDER=perplexity_sonar
IFRIT_PERPLEXITY_API_KEY=<secret-manager value>
IFRIT_RESEARCH_SONAR_MODEL=sonar
```

The configured `sonar` model is sent directly to Perplexity's Sonar Chat
Completions API. Provider credentials are never written to reports, context
stores, or repository files.

Use `--saist --saist-bin /path/to/datadog-saist` to add upstream DataDog SAIST
as a broad AI-native candidate source. It does not replace PlaidNox Deep Hunt.

## PostgreSQL

Production persistence uses SQLAlchemy 2.x with Psycopg 3. Set the URL through
the externally configured environment name:

```dotenv
PLAIDNOX_DATABASE_URL=postgresql+psycopg://user:password@postgres/code_scanning
```

The deployable schema is
the ordered set under
`src/plaidnox_sast/assets/migrations/postgresql/`. Apply it with
`plaidnox-sast migrate`; the runner records and verifies migration checksums.
When the database URL is configured, Security IR, Context Fabric, security
memory, sourced knowledge, hunt plans/tasks, findings, evidence, and finding
dependencies use PostgreSQL. The SQLite adapters are retained only for local
operation and isolated tests.

Production images should install the pinned Tree-sitter language pack during
the image build and run the parser smoke tests there. Workers must not download
grammars or other scanner components while processing customer source.

## Context Fabric

A durable `--context-store` keeps content-addressed symbols, a readable source
tree, structural relationships, security memories, and finding dependencies.
Accepted snapshots create immutable bases. Later snapshots create temporary,
SCM-neutral overlays from changed paths and revalidate only affected security
paths.

The store contains derived security context only: never provider keys, raw
prompts, raw model responses, or secret-file contents. See
[Context Fabric contract](docs/context-fabric.md) and
[research notes](docs/context-fabric-research.md).

Web research is source-validated before it becomes reusable RAG knowledge. It
can expand a hunt and explain current framework behavior, but it cannot confirm
or close a vulnerability without code evidence and Deep Hunt falsification.

## Prompt cache

Every generative call passes through the LiteLLM SDK. Prompt caching is owned by
the LiteLLM gateway and its configured model providers; the scanner does not
create a second response cache or retain security verdicts in process. Versioned Markdown templates rendered with Jinja keep stable operating instructions in the system prefix and put
repository/task evidence in the final user message. Reports expose only the
cache-token telemetry returned by LiteLLM. Context and sourced knowledge are
durable; vulnerability verdicts are not blindly cached.

The prompt corpus uses `.md` files under `src/plaidnox_sast/assets/prompts/operations/`
with shared methodology in `_partials/`. The manifest selects every system/user template;
application code contains no prompt paths or search expressions. It adapts VulnHunter's reconnaissance,
exhaustive input tracing, adversarial verification, reproduction reasoning, and
root-cause sweep discipline. Attribution is recorded in the repository `NOTICE.md`.

## Outputs

- `report.json` — normalized findings, route classification, deep-hunt evidence,
  policy decision, and metrics.
- `report.sarif` — SARIF 2.1.0 with context and model-tier metadata.
- `report.md` — readable assessment.
- `repository-context.json` — application architecture, source inventory, and
  readable source tree.

## Production worker and acceptance

The Phase 5/6 worker image and hardened Compose example are under
`docker/code-scanning/`. Production workers consume queued immutable local
snapshots, verify their tree hashes, maintain database leases, and write to a
separate output root. They do not clone source or own SCM behavior.

See [production operations](docs/CODE_SCANNING_OPERATIONS.md) for migrations,
signed assets, private-network deployment, recovery, retention, and telemetry.
See [the acceptance gate](docs/CODE_SCANNING_ACCEPTANCE.md) for repeatable
recall/precision/duplicate/cost scoring over completed reports.
