## Phase 2b/3 — adversarial verification gates and reproducibility

Apply these gates in order and record the evidence for each.

1. **Design invariant.** State the intended feature, expected authority/data boundary, and exact invariant alleged to fail. User choice is not a vulnerability when that choice is the feature.
2. **Production reachability.** Re-enumerate callers, registrations, wrappers, build/configuration branches, and indirect dispatch independently from discovery. Reject dead or exclusively non-production paths only with positive evidence. A development caller does not make a shared function development-only.
3. **Attacker control.** Prove the ultimate origin and required privilege for every influential value or omission. Continue through stores, queues, caches, service responses, DTOs, and transformations.
4. **Effective defense.** Inspect all relevant controls between origin and effect, including controls in callers and receivers. Prove exact ordering and context compatibility. A validator for one grammar, output context, resource, tenant, actor, or branch does not protect another.
5. **New capability.** Describe the concrete confidentiality, integrity, availability, privilege, cross-tenant, financial, policy, or workflow outcome gained beyond intended authority. A surprising implementation detail without a security outcome fails this gate. When this gate passes, also set the top-level `gained_capability` field to the single best-matching capability label from the capability taxonomy.
6. **Falsification.** Build the strongest benign explanation and actively search for the fact that would invalidate the finding. Record each attempted disproof and the evidence that passes, fails, or remains unknown. Unknown infrastructure cannot be treated as a defense.
7. **Reproduction.** Produce a safe, minimal proof plan with preconditions, controlled action, path, expected secure behavior, vulnerable behavior, and observable result. Never say a test ran unless execution evidence was supplied. Static proof must list every source-to-effect step.
8. **Remediation invariant.** Fix the failed boundary at the correct layer and across every affected path. Provide a regression test that fails before the fix and passes only when the invariant is restored, without encoding one sample payload.

A confirmed finding requires all gates to pass. It must identify the entry point, complete path, failed control, effect, preconditions, new capability, falsification attempts, proof plan, durable fix, and regression test with machine-checkable evidence. Any material unknown keeps the candidate unconfirmed. Use the most specific supported weakness class only after the behavior is proven.
