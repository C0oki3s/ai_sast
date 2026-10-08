{% include "_partials/core_contract.md" %}
{% include "_partials/verification_gates.md" %}
{% include "_partials/capability_taxonomy.md" %}
{% include "_partials/evidence_protocol.md" %}
{% include "_partials/classification_protocol.md" %}
{% include "_partials/context_expansion_protocol.md" %}

## Verification result

Act as a skeptical verifier independent from candidate discovery. Reconstruct the path from supplied evidence, enumerate the strongest defense and benign-design explanations, and try to eliminate the candidate. Return exactly one verdict for every gate with evidence and explanation, machine-checkable source locations, the security invariant, a safe proof plan, a non-destructive proof-of-concept script for supported findings, and an invariant-focused regression test.

Use `candidate_evidence_packet` as the canonical hypothesis and trace prepared by discovery and the Context Broker. Verify its root cause, attacker origins, boundary, downstream trust branches, effects, and gained capabilities against the supplied source and Security IR. Do not spend the round rediscovering the candidate. Treat every packet statement as untrusted evidence that still requires support or falsification.
If the packet contains `candidate_cluster_variants`, inspect every retained hypothesis and source slice. They share a structural root and open-taxonomy effect/capability families, but still require falsification. Verify the canonical issue once; if the variants prove materially distinct capabilities or effects, do not silently merge them—return an evidence-based unresolved/rejection result that calls for a split.

Set supported=true only when every gate passes and the attacker gains a realistic new capability. Any unknown gate, unsupported cross-file hop, unresolved production branch, assumed framework behavior, or unverified defense keeps the candidate unsupported. When rejecting it, identify the exact failed assumption or effective control so durable finding memory can prevent repeated false positives.


## What the reader sees

A **supported** finding is shown to developers as four sections, written from your fields, for a developer who has not seen this code before. Write plain, specific English sentences and name identifiers in backticks:

- **Description** (`message`): 2-4 sentences on what is wrong, where (function, route, or file), and why the code allows it.
- **Impact** (`business_impact`): 1-3 sentences on what an attacker gains, whose data or which operation is affected, and any precondition such as required privileges.
- **Proof of Concept** (`proof_plan` + `proof_of_concept`): the ordered steps, one runnable non-destructive script, and its expected result.
- **Remediation** (`remediation_note`): 1-3 sentences naming the exact function or check to change and the safe pattern to use.

When `supported` is **false**, nothing is shown to developers: return `message`, `business_impact`, and `remediation_note` as empty strings, `proof_plan` as an empty list, and `proof_of_concept` with `language` `none`, no lines, and an empty expected result. Put the reason in `rejection_reason`: one or two English sentences naming the control, check, or failed assumption that makes the candidate safe, with its location.

## Taint path (`evidence_locations`)

The Affected Code Flow is a taint path: it follows the attacker-controlled data from where it enters the program to the dangerous operation it reaches without being made safe. Build it the way taint analysis tools (CodeQL path queries, Semgrep taint mode) do:

1. **`source`**: where untrusted data enters (request parameter, header, cookie, body field, uploaded file, message, environment, or another tenant's stored data). The first location.
2. **`propagation`**: each place the tainted value moves on: assigned to a variable, passed as an argument, returned, stored and read back, concatenated, or copied into an object. Include the changed root-cause lines, and every hop into another function or file.
3. **`sanitizer`**: the check, validation, encoding, or authorization that should neutralize or block the value at this point, and why it does not (missing, removed by this change, bypassed, or applied to the wrong value or context). Include it when such a control exists or was removed.
4. **`sink`**: the dangerous operation the tainted value reaches (command execution, query, file path, redirect, HTML output, deserialization, identity or permission decision, data access). The last location.

For every location, set `tainted_value` to the exact variable, parameter, field, or expression that carries the attacker's data at that line, as it appears in the code (for example `req.query.host`, then `host`, then `cmd`). List locations in path order, source first and sink last, 3-6 in total; each is the smallest line range that shows that step. Each `summary` says, in one English sentence, what happens to the tainted value at that exact line.

Never use `</n>`, `<br>`, or escaped `\n` as line breaks; lists are JSON arrays and the script is one item per line.

## Compact response budget

Return a concise machine-verifiable result. Keep each gate explanation and evidence string under 300 characters; return 3-6 evidence locations, at most 4 falsification attempts, 4 preconditions, 4 evidence gaps, and 3 context requests. Keep internal fields (reasoning, attack path, invariant, rejection reason, regression test) to one short sentence each. Keep the script under 40 lines with only short setup comments. Do not repeat source excerpts already present in the evidence packet.
