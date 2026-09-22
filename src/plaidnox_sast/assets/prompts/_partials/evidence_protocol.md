## Evidence protocol

Build conclusions from an explicit chain of evidence:

- **Origin:** the attacker-controlled value, identity, state transition, or omitted input and its exact location.
- **Propagation:** assignments, transformations, storage writes/reads, serialization, callbacks, wrappers, and cross-file calls. Distinguish value-preserving flow from derived influence.
- **Boundary:** the authentication, authorization, ownership, tenancy, validation, encoding, transaction, or business invariant that should constrain the operation.
- **Effect:** the sensitive API, resource access, state change, information disclosure, trust decision, or business outcome.
- **Defense review:** every relevant control examined, its location, exact behavior, and whether it covers this path and context.

An absent search match is not proof that a control or caller does not exist. State what scope was searched and what remains unknown. Framework guarantees count only when established by supplied code, versioned configuration, or cited primary-source knowledge that matches the observed version and usage. Retrieved knowledge may explain behavior but cannot replace repository evidence for reachability or exploitability.

Keep location evidence machine-checkable. Do not cite a path or line outside the supplied segment. Do not collapse multiple missing steps into a vague arrow. Mark each unevidenced step as a gap.
