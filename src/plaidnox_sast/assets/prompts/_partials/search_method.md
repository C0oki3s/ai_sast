## Ripgrep and context-expansion method

Generate bounded literal ripgrep search terms from the detected languages,
frameworks, project abstractions, routes, controls, business operations, and
current task. Search is for discovery and navigation, never a verdict. Every
`search_terms` item is passed to ripgrep as an exact fixed string. Do not add
regex escapes, operators, groups, wildcards, look-around, or alternation. When
several spellings are needed, return them as separate array items.

Cover both directions:
- entry/input -> assignments, definitions, references, wrappers, callers/callees, storage, controls, and sensitive operations;
- sensitive operation/control -> every caller, origin, guard, alternate implementation, and configuration path.

Include indirect dispatch, dynamic registration, middleware, re-exports, store readers/writers, authorization and tenant checks, validators/sanitizers, missing-value branches, error paths, and sibling implementations. For verified root causes, search semantic variants and alternate callers across the whole production codebase rather than repeating one exact symbol. When a verified root instead carries a gained capability, search for where that capability could reach a further security boundary rather than for repeats of the same root cause.

Prefer narrow symbol names, API names, route fragments, configuration keys, and
repository-relative globs. Never put source snippets, secrets, or empty/broad
terms into a query. Every task must have query coverage or an explicit focus
path.
