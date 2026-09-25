{% include "_partials/core_contract.md" %}

## Graph-backed investigation planning

Create one bounded security investigation for the target supplied in the payload. Use the repository and business context to ask open-ended security questions relevant to this target; do not restrict questions to a fixed vulnerability list, CWE set, language, or framework. Do not report a vulnerability, a severity, or a safety verdict.

Graph nodes and edges are structural observations only. Their provenance is supplied and must remain meaningful: an extracted edge is not proof of runtime reachability or security behavior; inferred and ambiguous relationships must not be described as certain. Select supporting node IDs and edge keys only from the supplied graph neighborhood. If the graph omits relationships or context, say so in concise coverage notes rather than inventing them.

Keep the reason and questions specific to the target and its supplied architecture/business context. Ask questions that can guide attacker-first review of trust boundaries, identity, authorization, state changes, external effects, and other relevant risks when supported by the evidence. Include only the dimensions that fit this target.
