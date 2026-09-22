# PlaidNox security product workstreams

## Boundary rule

Code Scanning must reach its end-to-end exit condition before another scanner
family is added to its runtime. Every family below is an independent workstream
with its own adapters, workers, database schema, policy, versioning, tests, and
release gate. Products share only stable platform contracts:

- tenant, application, codebase, asset, and snapshot identity;
- evidence, finding, severity, lifecycle, ownership, and audit envelopes;
- policy decisions and report/export formats;
- object-storage references, telemetry, and cost attribution;
- an event contract for later correlation in VETA.

They do not share scanner-specific tables, queues, prompts, provider tokens, or
failure states. One scanner failing cannot silently make another scanner pass.

## Delivery order

1. Code Scanning (SAST and AI SAST).
2. SCM Integration.
3. Dependency Scanning (SCA) and SBOM.
4. Secrets Detection.
5. Outdated Software and automated upgrade intelligence.
6. IaC, container, VM, and Cloud Security.
7. License Risk.
8. DAST.
9. IDE Plugins.

This order establishes reliable source understanding and evidence contracts
before adding orchestration or more scanner families.

## 1. Code Scanning

Scope:

- broad AI-native source review across supported languages;
- PlaidNox proprietary prompts, context, taxonomy, and Deep Hunt methodology;
- organization-defined custom AI rules without hardcoded code paths;
- Context Fabric, business/threat context, knowledge RAG, and prompt caching;
- adversarial false-positive reduction for every candidate;
- evidence-bound remediation and AI-proposed fixes;
- JSON, SARIF, Markdown, and API-ready normalized findings.

Open-source foundations:

- DataDog SAIST as an optional broad AI candidate adapter;
- Tree-sitter for portable parsing;
- SCIP/compiler/LSP indexes where available for precise symbols/references;
- ripgrep for AI-directed discovery and navigation;
- a small persistent Tree-sitter Security IR for relationships and context selection.

PlaidNox owns task planning, context compilation, the recursive hunt loop,
falsification, finding schema, prompt assets, knowledge, and verdicts.

## 2. SCM Integration

Scope:

- GitHub, GitLab, Bitbucket, and Azure Repos adapters;
- app/install-token lifecycle, webhook verification, clone/snapshot acquisition;
- PR/MR diff and merge-base calculation;
- queueing, retries, cancellation, concurrency, checks/statuses, comments;
- protected default-branch configuration and policy acquisition;
- CI templates and audit linkage.

The SCM service invokes Code Scanning with an immutable source snapshot and
receives a result. Code Scanning never receives webhook or installation-token
logic. The earlier GitHub/PR prototype was removed from the Code Scanning
package; SCM starts later in its own package and database boundary.

## 3. Dependency Scanning (SCA) and SBOM

Scope:

- complete manifest/lockfile and artifact inventory across ecosystems;
- direct/transitive dependency paths and vulnerable-function reachability;
- OS and language packages, vendored code, containers, and SBOM ingestion;
- OSV/CVE/advisory correlation, VEX, exploit maturity, EPSS, and fix versions;
- CycloneDX and SPDX generation/import/export;
- upgrade suggestions, breaking-change intelligence, and fix verification;
- later CI/SCM integration through the SCM service.

Open-source foundations to evaluate behind adapters:

- OSV-Scanner and OSV.dev for ecosystem advisories, lockfiles, call analysis,
  license data, and guided remediation;
- Syft for package cataloguing and CycloneDX/SPDX SBOM generation;
- Grype and Trivy as independent vulnerability matchers;
- deps.dev for package/dependency metadata;
- cdxgen for additional ecosystem SBOM coverage.

Multiple matchers retain their provenance; PlaidNox must not merge conflicting
package identity assumptions into one unexplained result. Reachability uses the
Code Intelligence graph through a versioned interface, while SCA retains its own
schema and verdict.

## 4. Secrets Detection

Scope:

- working-tree, history, pre-commit, CI, and artifact scanning;
- structured and entropy-based detection with provider-specific validation;
- secret liveness checks through allowlisted, non-destructive provider adapters;
- revocation/rotation guidance and occurrence grouping;
- pre-commit blocking that never sends secret values to an LLM.

Open-source foundations:

- Gitleaks for configurable Git/source rules and pre-commit/CI scanning;
- TruffleHog for verified-provider detectors and history scanning;
- detect-secrets for baseline-oriented developer workflows.

Raw values are encrypted only when a short-lived liveness worker requires them;
reports, prompts, logs, and normal persistence contain fingerprints and redacted
evidence only.

## 5. Outdated Software and upgrade intelligence

Scope:

- current/latest/secure/EOL/approved-baseline versions;
- release age, maintenance state, deprecations, breaking API changes, and risk;
- Renovate-style update planning and OpenRewrite-style source transformations;
- test/build results from isolated execution workers;
- AI explanation and repair only after deterministic version and build evidence.

Open-source foundations:

- Renovate for update discovery and policy-driven proposal generation;
- OpenRewrite for structured source/build migrations;
- ecosystem package managers and release APIs;
- endoflife.date data where licensing and provenance are acceptable.

This is separate from SCA: software can be outdated without a known CVE, and an
SCA remediation may not be the newest available version.

## 6. IaC, container, VM, and Cloud Security

Scope:

- Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, and configuration
  misconfiguration analysis;
- container image, host/VM, Kubernetes cluster, and cloud-account posture;
- CSPM asset inventory, relationships, exposure, identity, network, data, and
  attack-path graph queries;
- drift between IaC intent and deployed state;
- cloud-specific remediation with evidence and account/region provenance.

Open-source foundations:

- Trivy, Checkov, and KICS behind normalized IaC adapters;
- Prowler for AWS/Azure/GCP posture and compliance evidence;
- Steampipe and/or CloudQuery for asset inventory and graph/query ingestion;
- kube-bench and kube-hunter for Kubernetes-specific evidence;
- Syft/Grype/Trivy for container and VM package inventory.

Cloud credentials are short-lived and scoped to read-only collection. Cloud
workers and data use a separate trust boundary from source-code workers.

## 7. License Risk

Scope:

- declared and detected licenses, SPDX expressions, copyrights, and notices;
- direct/transitive policy, copyleft/network-copyleft obligations, exceptions,
  source-availability requirements, and unknown-license review;
- SBOM-linked attribution and notice bundle generation;
- policy by product, distribution model, organization, and deployment context.

Open-source foundations:

- OSS Review Toolkit for scanner/advisor/evaluator/report workflows;
- ScanCode Toolkit for license and copyright detection;
- FOSSology for deeper review and clearing workflows;
- OSV-Scanner/Trivy license signals as additional attributed evidence.

Legal conclusions require organization policy and human review; classifier
output remains evidence, not an automatic license conclusion.

## 8. DAST

Scope:

- API and browser discovery, authenticated sessions, OpenAPI/GraphQL inputs;
- passive and active checks, safe scan policies, request/response evidence;
- staging-target ownership validation, rate limits, test data, and egress policy;
- source correlation through stable endpoint identifiers after both products are
  mature.

Open-source foundations:

- OWASP ZAP Automation Framework for repeatable passive/active plans;
- Nuclei for signed/versioned templates and narrowly scoped checks;
- Schemathesis for property-based OpenAPI/GraphQL API testing;
- testssl.sh for TLS configuration evidence.

DAST requires explicit target authorization and an execution environment. It is
never embedded inside the read-only Code Scanning worker.

## 9. IDE Plugins

Scope:

- VS Code, JetBrains, and a generic Language Server Protocol client;
- local changed-file Code Scanning, secret pre-checks, and server result sync;
- evidence, suppression, remediation preview, and policy explanations;
- no long-lived provider or cloud credentials in the editor.

Build a shared LSP/backend protocol first, then thin editor clients. IDE release
cycles and telemetry remain independent from scanner releases.

## Cross-product PostgreSQL rule

Each workstream owns a separate table prefix or PostgreSQL schema. Shared asset
identity is referenced through stable IDs and events, not cross-product write
access. Initial namespaces:

```text
code_scanning_*
scm_*
sca_*
secrets_*
software_*
cloud_*
license_*
dast_*
ide_*
```

The Code Scanning migration must never create the deferred namespaces.
