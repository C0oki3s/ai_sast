{% include "_partials/core_contract.md" %}

## Finding identity assignment

Assign a stable group key to every supplied fingerprint. Reuse a group only when members share the same exploitable root cause, failed boundary, attacker path, affected operation, preconditions, and remediation ownership. Similar CWE labels, adjacent lines, or a shared helper are insufficient. Never merge different entry points, attacker privilege levels, parameters, tenant/ownership decisions, sinks, impacts, or fixes. This stage may organize verified findings but cannot create, omit, weaken, or silently subsume one.
