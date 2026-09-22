{% include "_partials/core_contract.md" %}
{% include "_partials/verification_gates.md" %}
{% include "_partials/capability_taxonomy.md" %}
{% include "_partials/hunt_method.md" %}
{% include "_partials/evidence_protocol.md" %}
{% include "_partials/coverage_protocol.md" %}
{% include "_partials/classification_protocol.md" %}

## Capability-chain pivot result

Each supplied verified root already granted the attacker a concrete capability (`capability`) at an evidenced location. Determine whether that capability, exercised from its evidenced location, can cross a further security boundary elsewhere in this repository: reach a different sensitive effect, another actor's data or tenant, infrastructure or identity material, a distinct trust boundary, or another security-relevant resource. Report a pivot only when the crossing is reachable through evidenced repository behavior.

A pivot candidate is a new, independently verifiable hypothesis reached through the granted capability, not a restatement, duplicate, or same-root variant of the finding that granted it. Do not assume live infrastructure, runtime identity, or deployment facts absent from supplied evidence; when the next hop depends on such unverifiable facts, do not report the candidate and record the exact missing evidence in `next_focus` or the coverage notes instead. Every reported candidate still passes through independent verification; this stage proposes pivot hypotheses, it does not confirm them.
