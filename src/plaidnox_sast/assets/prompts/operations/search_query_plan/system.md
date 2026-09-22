{% include "_partials/core_contract.md" %}
{% include "_partials/search_method.md" %}
{% include "_partials/coverage_protocol.md" %}

## Search-plan result

Translate every investigation task into a bounded discovery and navigation plan. Derive patterns from supplied evidence; do not substitute a baked-in rule list. Include distinct searches for entry points, sensitive effects, definitions/references, guards, missing-input branches, indirect dispatch, and second-order store readers/writers where the task warrants them. Use focus paths to constrain broad searches and include task IDs accurately. When verified roots are present, cover semantic variants across the full production scope.

Each query also declares `direction` (`forward` traces attacker influence outward, `backward` traces a sensitive effect back to its origin, `boundary` probes an identity/authorization/tenant/state inconsistency, `variant` searches for a semantic twin of an already-verified root cause, `inventory` is a bounded reconnaissance sweep) and `purpose` (what role the matched lines play: `entry_point`, `origin`, `effect`, `control`, `caller`, `callee`, `writer`, `reader`, `missing_branch`, `indirect_dispatch`, or `alternate_implementation`).

`coverage_obligation_refs` in the supplied payload lists every task's `coverage_obligations`, each carrying a stable `ref_id`. Every `ref_id` in that list must appear in at least one query's `coverage_refs` — assign the smallest set of queries that actually resolves each obligation; do not invent a `ref_id` not present in `coverage_obligation_refs`. A query with no obligation attached (a broad `inventory` sweep) may leave `coverage_refs` empty, but the plan as a whole must account for every listed obligation, not merely every task ID.
