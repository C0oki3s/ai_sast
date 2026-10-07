# GitHub bot integration

`PlaidNox/plaidnox-github-bot` is the GitHub-facing service. `ai_sast` is the
review API and scanner. Keep this boundary strict.

```text
GitHub
  -> plaidnox-github-bot
     webhook signature + delivery identity
     installation authentication
     PR event normalization
     check run / inline comment publication
     current-HEAD and stale-result checks
  -> POST ai_sast /v1/reviews
     immutable source acquisition from an internal mirror/broker
     contextual changed-file review
     independent Deep Hunt verification
     baseline classification
     deterministic merge policy
  -> canonical review response
  -> plaidnox-github-bot publishes to GitHub
```

## API server configuration

The `plaidnox-scm-api` entrypoint requires:

```dotenv
PLAIDNOX_SCM_API_TOKEN=<secret shared only with the bot>
PLAIDNOX_SCM_REPOSITORY_ROOT=/srv/plaidnox/repositories
PLAIDNOX_DATABASE_URL=postgresql+psycopg://user:password@postgres/code_scanning
LITELLM_API_KEY=<gateway virtual key>
LITELLM_API_BASE=http://litellm:4000
```

The bot configures the same secret as `PLAIDNOX_SAST_API_TOKEN` and calls the
scanner URL configured in `PLAIDNOX_SAST_API_URL`.

The mirror layout is:

```text
<PLAIDNOX_SCM_REPOSITORY_ROOT>/<provider>/<repository_id>
```

The source broker that synchronizes those mirrors is an infrastructure
boundary. It must make the full base and head SHAs available before dispatching
the review request. The scanner does not fetch with a GitHub installation token
and does not accept mutable branch names as scan identity.

## Contract

`POST /v1/reviews` accepts the normalized fields documented in the bot's
`docs/AI_SAST_INTEGRATION.md`. Authentication uses a bearer token. Unknown
fields are rejected.

The response always repeats the requested immutable `head_sha`. Actions are:

```text
allow
warn
block
require_security_approval
incomplete
```

Only independently verified current-review findings are returned as finding
objects. An unresolved required stage returns `incomplete`, never `allow`.
Provider credentials and raw detected secrets are absent from both directions.

## Ownership

Changes to webhook signatures, GitHub App permissions, installation tokens,
check runs, review comments, GitHub patch anchoring, and stale-HEAD publication
belong in `PlaidNox/plaidnox-github-bot`.

Changes to review orchestration, source-broker interfaces, AI review, Deep Hunt,
baseline comparison, policy evaluation, and canonical findings belong in
`ai_sast/src/plaidnox_scm`.

## Additive contract fields (dashboard data)

These are optional and backwards compatible; a bot that ignores them keeps working.

- Request: `author_login` (PR author's provider login). Stored on
  `scm_review_attempts` with `head_ref`, `base_ref` and `repository_full_name`
  so the dashboard can show branch and author. **Bot change needed:** send
  `pull_request.user.login` as `author_login`.
- Response finding: `classification_references` (CWE/OWASP), emitted only when
  the verifier produced them.
- Response `evidence_trace.nodes[]`: `code`, `code_start_line`, `code_end_line`
  — the redacted source window around each taint node, captured at verification
  time and persisted with the finding. Bots that validate trace nodes strictly
  must accept these keys.
- `proof_of_concept` is now always present on a verified finding that has a
  proof plan (steps only when the verifier returned no script).
- Per-run timeline: each review records stage events (`snapshot_ready`,
  `changes_analyzed`, `context_ready`, `candidates_generated`,
  `verification_complete`, `baseline_compared`, `policy_evaluated`) in
  `scm_activity_events` with the run's `review_id` and stage details in
  `metadata`.
