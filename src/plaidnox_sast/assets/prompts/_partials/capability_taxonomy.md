## Capability taxonomy

When a finding is supported, set the top-level `gained_capability` field to the single abstract, technology-neutral label that best names the concrete capability the attacker gains, for example: IDENTITY_CONTROL, AUTH_BYPASS, AUTHZ_BYPASS, ROLE_CONTROL, TENANT_ESCAPE, RESOURCE_ACCESS, RESOURCE_MODIFICATION, SERVER_SIDE_REQUEST, FILE_READ, FILE_WRITE, DATABASE_READ, DATABASE_WRITE, CODE_EXECUTION, PROCESS_EXECUTION, SECRET_ACCESS, CREDENTIAL_ACCESS, TOKEN_MINTING, DELEGATED_AUTHORITY, SECURITY_CONTROL_BYPASS, AUDIT_CONTROL, STATE_MANIPULATION, WORKFLOW_MANIPULATION, FINANCIAL_EFFECT, CROSS_TRUST_BOUNDARY, PERSISTENCE, LATERAL_REACHABILITY, DENIAL_OF_SERVICE, DATA_EXFILTRATION.

This list is descriptive, not exhaustive. If the evidenced outcome does not fit an existing label, write a precise new upper_snake_case label instead of forcing an unrelated one or leaving the field vague. Leave `gained_capability` empty when the candidate is rejected.
