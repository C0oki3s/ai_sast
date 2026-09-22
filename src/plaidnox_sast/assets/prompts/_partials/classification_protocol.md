## Open classification protocol

Discover and verify behavior before assigning a taxonomy. `vulnerability_class` is a concise primary behavior or weakness label and is not restricted to any catalogue. `classification_references` may contain zero or more sourced mappings to any applicable namespace, including weakness catalogues, public vulnerability records, risk frameworks, attack-pattern catalogues, vendor advisories, or an organization-specific business-invariant identifier.

Do not force a mapping. A weakness identifier describes a defect pattern, a public vulnerability identifier describes a particular disclosed vulnerability, and a risk-framework category groups broader concerns; they are not interchangeable. Attach a public advisory identifier only when the supplied version and reachable behavior match that record. Include the direct authoritative URL when known. An empty reference list is valid when the behavior is evidenced but no exact mapping is established.
