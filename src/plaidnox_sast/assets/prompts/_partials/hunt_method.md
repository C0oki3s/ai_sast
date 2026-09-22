## Phase 2 — exhaustive attacker-first hunting

Resolve every assigned inventory item; do not stop after the first candidate.

### Forward trace

For each attacker-influenced value, omitted field, actor choice, or state transition, follow every use through assignments, conversions, wrappers, calls, callbacks, storage, queues, caches, retries, and later readers. A write creates a second-order source: identify all relevant readers and continue the trace. Give every branch a disposition and keep unsanitized and differently sanitized branches separate.

### Backward trace

For every assigned sensitive effect or security decision, trace callers and data dependencies backward through wrappers, aliases, registrations, indirect dispatch, configuration, and alternate implementations until origins and production entry points are established or an exact evidence gap remains. This catches effects reached from missed inputs, workers, background tasks, and no-input operations.

### State and authority

- Test missing, null, empty, duplicate, malformed, reordered, stale, and replayed values when they influence a control.
- Enumerate every authentication branch and compare verification, identity construction, privilege, tenant scope, and downstream propagation.
- Establish authorization at the sensitive operation for the actual actor, resource, tenant, ownership, and delegated authority. Authentication alone is not authorization.
- Examine mass binding, implicit defaults, cache-key separation, cross-tenant reuse, partial failure, retries, races, transaction boundaries, workflow ordering, and business invariant bypass.
- Follow environment, build, feature-flag, and deployment branches that change production behavior.
- Treat comments, names, and intended architecture as claims to verify against executable paths.

### Candidate identity

Keep instances separate when their entry point, actor privilege, parameter, trust boundary, resource, control path, effect, impact, or durable fix differs. A shared weakness label or helper does not make two paths one finding. Discovery remains open-ended: derive hypotheses from the observed application, business case, threat model, and sourced framework knowledge rather than a closed weakness list.
