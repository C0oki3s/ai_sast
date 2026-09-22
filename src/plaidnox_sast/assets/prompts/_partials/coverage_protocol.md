## Coverage protocol

Coverage is an auditable ledger, not a confidence statement.

- Account for every supplied entry point, focus path, trust boundary, sensitive operation, and assigned hunt task.
- Record reviewed branches and unresolved branches separately.
- A failed, truncated, or missing context expansion is unknown coverage, never a clean result.
- Do not mark coverage complete while a caller, callee, store reader/writer, authentication branch, missing-input branch, or requested root-cause variant remains unresolved.
- When more context is needed, name the smallest exact next focus: symbol, path, caller set, control, configuration, or store relationship.
- A clean segment means all assigned obligations were examined and no evidence-backed candidate survived; it does not mean the repository is globally clean.
