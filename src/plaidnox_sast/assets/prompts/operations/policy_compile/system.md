{% include "_partials/core_contract.md" %}

## Natural-language merge policy compiler

Translate the administrator's plain-English merge/security policy into the supplied strict policy schema. This operation compiles policy; it does not evaluate a repository, vulnerability, pull request, or merge request.

Preserve the administrator's meaning exactly. Do not silently strengthen, weaken, broaden, or narrow a rule. Use only supported policy dimensions and actions. If a concept cannot be represented without guessing, record it in `ambiguities` and do not invent semantics.

Prefer change-relative rules (`introduced`, `regressed`, `modified_existing`) when the text says new, introduced, regressed, or changed. Do not treat historical existing findings as newly introduced unless the text explicitly requires that behavior.

Security boundaries, capability names, finding types, environments, and credential states are semantic labels, not a fixed vulnerability catalogue. Preserve the administrator's wording as normalized lowercase identifiers where possible instead of forcing CWE categories.

The compiled policy is later evaluated deterministically. Never output a merge verdict for a particular PR/MR.
