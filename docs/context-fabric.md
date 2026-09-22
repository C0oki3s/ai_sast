# Code Scanning Context Fabric contract

Context Fabric stores derived source/security understanding. It never stores
provider credentials, raw prompts, raw model responses, or unredacted secrets.

## Production persistence

PostgreSQL is the production store through the SQLAlchemy models under
`plaidnox_sast.persistence`. Its ordered deployable migration is:

- `src/plaidnox_sast/assets/migrations/postgresql/0001_code_scanning_core.sql`

The existing SQLite migrations and `ContextFabricStore` remain a transitional
local/test adapter while ORM repositories are completed. They are not the
production deployment contract.

## Snapshot lifecycle

- A context base is immutable and keyed by codebase and source revision.
- A later immutable source snapshot creates a generic overlay of changed
  symbols and edges, independent of GitHub/GitLab or PR/MR concepts.
- Stable symbol IDs do not include content hashes; content hashes determine
  whether a symbol version changed.
- Reverse dependencies identify callers, controls, paths, and findings that
  require revalidation.
- An accepted overlay becomes a new immutable base; abandoned overlays expire.
- Security memories are scoped and active only when explicitly recorded.
- Finding links are dependencies, never an automatic closure mechanism.

## Code reading

AI-created ripgrep queries are the primary discovery mechanism. Tree-sitter
maintains a compact Security IR of symbols, imports, calls, routes, and selected
security facts. The Context Compiler expands a search hit to the smallest
complete code slice using the enclosing symbol and relevant relationships.

Precise compiler/LSP indexes and targeted dataflow adapters can enrich the IR
for a specific question without changing the Context Fabric contract.

## Recursive analysis

- The LLM creates search queries for every hunt task from repository, business,
  threat, and knowledge context.
- Discovery continues for each focused slice until the model reports complete
  coverage or reaches the configured continuation limit.
- Every candidate is independently falsified by PlaidNox Deep Hunt.
- Newly verified root causes create a new AI search plan for semantic variants.
- Only unseen candidate fingerprints enter the next round.
- The recursive loop ends at a fixed point; any search, model, coverage, or
  sweep failure marks the scan incomplete.

JEV chooses durable knowledge reuse, broader retrieval, or sourced Perplexity
research. Only provider-returned source URLs are persisted. Research and memory
guide the hunt but cannot confirm a finding without code evidence.
