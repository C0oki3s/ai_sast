# Prompt contracts

## Prompt layout

Use one manifest-listed operation with a stable `system.md` and dynamic `user.md`. Markdown files may contain Jinja includes and variables, and every prompt keeps the `.md` extension.

1. Stable operating contract and prompt-injection boundary.
2. Only the methodology needed by this operation.
3. Dynamic evidence serialized as JSON in the final user message.
4. A strict external JSON schema for the response.

Jinja uses `StrictUndefined`. A missing variable or operation is an error. Keep prompt paths in the prompt manifest rather than constructing them in orchestration code.

## Reconnaissance

Require evidence-backed application boundaries, actors, entry points, input surfaces, sensitive assets, trust boundaries, identity controls, data stores, external services, business workflows, security invariants, and explicit coverage gaps. A zero-input sensitive endpoint is still an attack-surface obligation.

## Hunt planning and discovery

Create tasks from the observed architecture and business context instead of a closed CWE list. Every task owns explicit paths/entry points, business invariants, coverage obligations, confirmation evidence, falsification evidence, and knowledge questions.

Trace in both directions:

- forward from every attacker-controlled or omitted input through all branches and second-order stores;
- backward from sensitive effects through callers, wrappers, indirect dispatch, guards, and origins.

A search hit is a lead. Candidate evidence records origin, propagation, expected boundary, sensitive effect, controls checked, and missing evidence.

## Verification

The independent verifier returns exactly one result for each gate:

1. design and violated invariant;
2. production reachability;
3. attacker control;
4. effective context-matched defenses;
5. new capability and concrete impact;
6. adversarial falsification;
7. safe reproduction reasoning;
8. remediation invariant and regression test.

A supported finding requires all gates to pass, machine-checkable evidence locations within supplied code, an explicit invariant, proof plan, and regression test. An unsupported finding requires an evidence-backed rejection reason. Unknown evidence never becomes confidence.

## Coverage and sweep

Coverage is a ledger. A failed or truncated branch is unknown, not clean. Continue with the smallest exact next focus until assigned entry points, callers/callees, stores, control branches, and root-cause variants are accounted for.

## Research

Research only time-sensitive or version-specific questions unresolved by stored knowledge. Prefer first-party sources and match the observed version/configuration. One stored statement needs one supporting source. Never send source code, internal names, tenant data, or credentials to web search.

Primary references:

- OWASP Secure Coding with AI: https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_with_AI_Cheat_Sheet.html
- OWASP Prompt Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- Capital One VulnHunter: https://github.com/capitalone/vulnhunter
- CodeQL data-flow concepts: https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/
- NIST SSDF: https://doi.org/10.6028/NIST.SP.800-218
