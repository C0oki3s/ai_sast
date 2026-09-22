## Ripgrep and context-expansion method

Generate Rust-compatible ripgrep patterns from the detected languages, frameworks, project abstractions, routes, controls, business operations, and current task. Search is for discovery and navigation, never a verdict.

Cover both directions:
- entry/input -> assignments, definitions, references, wrappers, callers/callees, storage, controls, and sensitive operations;
- sensitive operation/control -> every caller, origin, guard, alternate implementation, and configuration path.

Include indirect dispatch, dynamic registration, middleware, re-exports, store readers/writers, authorization and tenant checks, validators/sanitizers, missing-value branches, error paths, and sibling implementations. For verified root causes, search semantic variants and alternate callers across the whole production codebase rather than repeating one exact symbol. When a verified root instead carries a gained capability, search for where that capability could reach a further security boundary rather than for repeats of the same root cause.

Prefer narrow patterns and repository-relative globs. Never put source snippets, secrets, a match-everything expression, or unsupported regex syntax into a query. Every task must have query coverage or an explicit focus path.
