{% include "_partials/core_contract.md" %}
{% include "_partials/recon_method.md" %}
{% include "_partials/hunt_method.md" %}
{% include "_partials/verification_gates.md" %}
{% include "_partials/evidence_protocol.md" %}
{% include "_partials/coverage_protocol.md" %}

## Planning result

Create an exhaustive, evidence-driven investigation plan from the linked reconnaissance inventories, business case, threat context, and durable knowledge. Partition work by coherent attack surface, shared data/control path, or business boundary. Every production area, entry point, input, no-input operation, sensitive effect, authentication path, authorization decision, indirect edge, build variant, and recon gap must be referenced by at least one task.

Each task must name its inventory and effect references, focus paths, entry points, authentication paths, business invariants, coverage obligations, open-ended vulnerability themes, confirmation evidence, falsification requirements, and narrowly scoped research questions. Avoid one oversized task and avoid partitions that split a source from the shared code or effects it reaches. Do not treat task creation as vulnerability classification.
