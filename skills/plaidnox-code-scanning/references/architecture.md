# Architecture boundaries

## Current Code Scanning pipeline

```text
immutable source snapshot
  -> readable tree + Tree-sitter Security IR
  -> Context Fabric base/overlay update
  -> AI repository context
  -> AI hunt plan
  -> JEV knowledge decision
  -> durable knowledge or Perplexity Sonar research through LiteLLM
  -> AI-planned ripgrep discovery
  -> evidence candidates
  -> independent Deep Hunt gates
  -> root-cause variant sweep
  -> evidence-preserving consolidation
  -> policy + JSON/SARIF/Markdown
```

## Component responsibilities

- `rg`: fast AI-directed discovery and navigation.
- Tree-sitter: compact symbols, calls, imports, routes, and structural context. It does not issue vulnerability verdicts.
- Context Fabric: durable source identity, relationships, threat context, security memory, finding dependencies, and snapshot overlays.
- JEV: typed decisions for context profile, depth, knowledge reuse/retrieval/research, and stable model tier.
- LiteLLM: the only generative model interface and owner of prompt-cache behavior/telemetry.
- Perplexity Sonar: current web-grounded security research through LiteLLM.
- SAIST: optional broad AI candidate source. PlaidNox owns validation and final findings.
- Deep Hunt: mandatory attacker-first verification, falsification, evidence, proof reasoning, remediation, and variant discovery.

## Persistence

Production uses SQLAlchemy 2.x and PostgreSQL. Runtime code uses typed repositories and transactions. DDL and SQL migration text remain in standalone files. SQLite is limited to explicitly labelled local/test adapters.

Keep source identity stable across edits. Store content hashes separately. A new snapshot changes only affected Security IR relationships, context packets, tasks, and finding dependencies. Never reuse a verdict after a relevant dependency changes.

## Product boundaries

SCM integration, SCA, secret detection, DAST, cloud/container/IaC, license risk, outdated software, and IDE plugins remain separate workstreams with separate tables, queues, prompts, credentials, and lifecycle rules.
