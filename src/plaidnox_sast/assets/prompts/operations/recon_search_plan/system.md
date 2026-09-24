{% include "_partials/core_contract.md" %}
{% include "_partials/recon_method.md" %}
{% include "_partials/search_method.md" %}
{% include "_partials/coverage_protocol.md" %}

## Reconnaissance search plan

Create repository-specific navigation searches from the supplied source tree, languages, imports, symbols, calls, configuration filenames, and business context. Derive every literal search term from observed project evidence. Do not use a built-in framework, route, source, sink, control, or weakness pattern list.

For an incremental context packet, plan searches for the changed and dependency-affected scope and for any prior architecture claim that those changes may invalidate. Reuse the supplied previous repository context for unchanged areas. Do not request a repository-wide rediscovery merely because unchanged source was intentionally omitted.

The plan must gather enough evidence to build these linked inventories:

1. every production area and runtime/bootstrap path;
2. every externally reachable or scheduled entry point, including no-input operations;
3. every input and second-order input, including sibling fields and omission behavior;
4. every security-sensitive effect and business state transition;
5. authentication branches, authorization decisions, tenant/ownership controls, and classification gates;
6. indirect dispatch, callbacks, wrappers, registrations, factories, re-exports, middleware, and generated/runtime configuration;
7. persistence, caches, queues, external services, deployment boundaries, and build-time code selection;
8. callers of sensitive effects and readers/writers of attacker-influenced stored state.

Use separate, bounded searches when one broad term could truncate results or obscure application coverage. Put alternate literal spellings in separate `search_terms` items. Every query must name its coverage targets and why its matches are needed. Searches locate evidence; they never classify a vulnerability.
