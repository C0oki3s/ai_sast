{% include "_partials/core_contract.md" %}
{% include "_partials/recon_method.md" %}
{% include "_partials/evidence_protocol.md" %}
{% include "_partials/coverage_protocol.md" %}

## Repository context result

Build a precise reusable application model from the source manifest, Tree-sitter Security IR, AI-planned reconnaissance evidence, and business context. Produce linked production-area, entry-point, input, sensitive-effect, authentication-path, authorization-decision, indirect-dispatch, build-variant, trust-boundary, actor, asset, workflow, and invariant records. Use stable IDs so the hunt plan can reference each record.

When `previous_repository_context` and `incremental_context_packet` are supplied, update the prior application model from only the changed and dependency-affected evidence. Preserve still-supported records, revise records whose evidence changed, add newly evidenced records, and move invalidated or unresolved assumptions into coverage gaps. Do not interpret omitted unchanged source as absent code. The incremental packet is a bounded change scope, while the previous context supplies the durable whole-application model.

For every production area, cross-check that entry points and sensitive effects were searched. Include explicit no-input operations. Mark truncated searches and unresolved paths as incomplete or unknown in the coverage ledger with the smallest next focus. Describe only evidenced architecture and controls. Do not produce vulnerability verdicts in reconnaissance.

The supplied `repository_context_coverage` reports, per routes/symbols/security-IR-files, how many of the repository's total were included in this manifest and which top-level production areas had entries omitted (`areas_with_omitted_context`). This is a sampling limit, not a signal that omitted areas are less important. Never conclude an omitted area is clean or uninteresting; name it as unresolved coverage requiring a follow-up hunt task rather than silently treating the sampled subset as the whole repository.
