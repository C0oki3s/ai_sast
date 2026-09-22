# Context Fabric research notes

The implementation deliberately combines techniques that are independently
useful rather than treating SAIST or VulnHunter as a complete platform.

| Reference | Verified capability | PlaidNox decision |
| --- | --- | --- |
| [GitHub CodeQL incremental analysis](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/incremental-analysis) | Base databases plus changed-file overlays avoid rebuilding unchanged analysis. | Use SCM-neutral immutable Context Bases and temporary source-snapshot overlays. |
| [SonarQube incremental analysis](https://docs.sonarsource.com/sonarqube-server/2025.5/analyzing-source-code/incremental-analysis/introduction) | Cache reuse considers cross-file dependencies, quality profiles, and build settings. | Invalidate paths/findings for dependency and policy changes, not just edited files. |
| [Snyk CodeReduce](https://snyk.io/blog/deepcode-ai-vulnerability-autofixing/) | Program analysis can reduce an LLM input to code needed for the issue and its context. | Compile a minimal `SecurityContextPacket`; never send a repository by default. |
| [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) | Fast incremental parsing and structural queries across languages. | Persist a small Security IR and expand only code selected by AI-directed ripgrep searches. |
| [DataDog SAIST](https://github.com/DataDog/datadog-saist) | Preview AI-native SAST with context-aware analysis and SARIF output. | Use it for broad candidate generation behind a PlaidNox SARIF normalizer; own the persistent context and rules in production. |
| [Capital One VulnHunter](https://github.com/capitalone/vulnhunter) | Attacker-first exploration and structured falsification for evidence-backed confirmed findings. | Rebuild the methodology as PlaidNox Deep Hunt for every readable candidate; do not vendor its runtime. |

## Product comparison

SAIST and VulnHunter are complementary. SAIST is suited to broad candidate
detection and standard output. VulnHunter is designed to reason from attacker
entry points, challenge its own hypotheses, and produce evidence-backed deep
findings. Neither is a durable repository/application context store.

The PlaidNox differentiator is therefore the Context Fabric: a versioned,
incremental code and security model used by broad discovery, deep review, and
triage. The MVP implementation establishes the base/overlay, memory,
dependency-link, and minimal-context contracts while keeping model execution
provider-neutral.

## Guardrails

- Context bases and overlays contain derived source context only; API keys,
  raw prompts, and raw model responses are not stored.
- Security memories are versioned and scoped. They influence triage but do not
  auto-close findings.
- JEV chooses stable PlaidNox tiers, not provider/model identifiers.
- PlaidNox Deep Hunt is mandatory for every reportable finding.
- Perplexity research is accepted only when its source URL is present in the
  Agent API search-result output; research alone cannot confirm a finding.
- Every generative call uses versioned Jinja templates through LiteLLM. LiteLLM
  owns prompt caching, and the scanner records provider cache telemetry without
  storing prompt responses or security verdicts locally.
- JEV routing remains a separate typed-decision request and has no application
  prompt cache.
