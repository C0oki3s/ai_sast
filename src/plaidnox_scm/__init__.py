"""SCM Integration: PR/MR security review, kept separate from Code Scanning.

Code Scanning (`plaidnox_sast`) remains an immutable-snapshot analysis API
with no provider-specific orchestration. This package imports it as a
library and owns everything SCM/PR-specific: diffing, the deterministic
ChangeRelevance gate, base-bound ApplicationContext, changed-file L1 review,
independent verification, and the provider-neutral review API. Provider
webhooks, installation credentials, and result publication live in separate
adapter services such as `PlaidNox/plaidnox-github-bot`.
"""
