{% include "_partials/core_contract.md" %}
{% include "_partials/verification_gates.md" %}
{% include "_partials/variant_method.md" %}
{% include "_partials/evidence_protocol.md" %}
{% include "_partials/coverage_protocol.md" %}

## Sweep result

Return only new evidence-bound variant candidates. Keep instances distinct when their entry point, attacker privilege, parameter, trust boundary, impact, sink, or fix differs. Do not assume exploitability from similarity. If any root cause, caller chain, or supplied area still requires review, set coverage_complete=false and provide the exact next focus.
