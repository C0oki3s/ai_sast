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
- `evidence_trace.nodes[].step`: 1-based position in the attack path, source
  first. Order nodes by `step` when present (older traces have no `step`).
- Proof of concept format (prompt contract 2026-10-08.1): `### Steps to
  Reproduce`, numbered steps, one fenced script (`bash`, `http`, `python` or
  `javascript`) and an `**Expected result:**` line. The verifier returns the
  script as one item per line, so `</n>`/escaped `\n` no longer appear. Before
  storage the script is redacted value-by-value (placeholders such as
  `$AUTH_TOKEN` are kept), checked for destructive commands and syntax-checked
  (bash `-n`, Python `compile`); a script that fails is withheld, the steps are
  kept, and the reason is added to `evidence_gaps`.
- Reader-facing sections: `description`, `impact`, `proof_of_concept`,
  `remediation`. Other text fields stay in the response for tooling.
- Code shown to people (`vulnerable_snippet.code`, trace `code`/`expression`)
  is redacted with `redact_code`: only hard-coded string secrets and known
  token formats are replaced, so a line such as
  `const token = req.headers.authorization` is kept intact.
- Per-run timeline: each review records stage events (`snapshot_ready`,
  `changes_analyzed`, `context_ready`, `candidates_generated`,
  `verification_complete`, `baseline_compared`, `policy_evaluated`) in
  `scm_activity_events` with the run's `review_id` and stage details in
  `metadata`.

## Finding lifecycle across pushes and pull requests

Modelled on GitHub code scanning, SonarQube and Semgrep: one stable identity per
finding; *fixed* is per scope (a PR, or the default branch); a human dismissal
survives later scans; a fixed finding that comes back is reopened.

| Situation | Result |
| --- | --- |
| Same bug reported again (reworded, lines moved) | Same `finding_id`; listed once; one PR comment. |
| Earlier push found it, this push did not, file unchanged | Still open, returned with `lifecycle: "carried_forward"`, still counts for merge policy. An LLM not repeating itself is not a fix. |
| File changed since it was last verified | Re-verified at the new commit. Verified: still open. Rejected: **fixed in this PR**. Inconclusive: stays open. |
| Root-cause file deleted (complete run) | Fixed in this PR. |
| Run incomplete / re-check budget used | Stays open, unchanged. An incomplete run never records a fix, not even for a deleted file. |
| Fixed, then reintroduced | Reopened (same id, `reopened_count` + 1). |
| Marked false positive / accepted risk | Stays that way; policy honours it. |
| `!fixed` claimed | Resolved in triage only when a later run or the merge proves the fix; otherwise the per-scope status shows "fixed". A resolved finding reported again is reopened. |
| PR merged | Its open findings become default-branch findings; findings it fixed are fixed on the branch (and a `!fixed` claim on them is resolved). |
| PR closed without merging | Its open findings are closed; the branch is untouched. |
| PR reopened | Its closed findings are open and tracked again. |
| A review finishes after the PR closed or merged | Its result is returned, but it changes no finding status or triage. |
| Default-branch bug fixed in a later PR | That PR re-verifies it when it touches the file; RESOLVED in the PR; fixed on the branch only when the PR merges. |
| Same bug open in two PRs | Same id; fixed status is tracked per PR, triage is shared. |

State lives in `scm_finding_occurrences` (scope `pr:<number>` or `branch`).
Merge/close arrives through the existing `pull_request` `closed` webhook claim.

Durability: a review's completion, its triage changes and its finding statuses are
committed in one transaction; if that fails the attempt is marked failed and a retry
runs the review again. The merge/close update is part of the webhook delivery claim's
transaction; if it fails the delivery is not recorded, so a redelivery applies it.
Review runs and merge/close/reopen events lock the PR's row in
`scm_pull_request_states`, so a review that started before the PR closed cannot set
its findings back to open, whatever order the two transactions commit in.

A carried-forward finding is always in the response (it still counts for merge
policy). If its stored data no longer validates, invalid optional fields are dropped,
or a minimal finding is rebuilt from its identity and location, with an evidence gap
saying so.
