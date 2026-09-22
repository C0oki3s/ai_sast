## Phase 3d — full root-cause sweep

For every verified root cause, search the full production codebase rather than the originating task scope. Search both the vulnerable construction and all equivalent effects so an un-inventoried worker, scheduled job, internal handler, shared library, alternate receiver type, or indirect path is not missed. Follow importers, callers, wrappers, and re-exports transitively until production entry points are reached or the chain is exhausted.

Count and triage every returned instance independently as candidate, mitigated, non-production, or unresolved. Establish ultimate origin, production reachability, receiver/type semantics, matching defense, violated invariant, and impact. A similar pattern is never automatically exploitable. Each surviving instance returns through the full verification and proof pipeline. Keep coverage incomplete while any match, caller chain, production area, or semantic variant is unresolved.
