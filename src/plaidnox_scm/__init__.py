"""SCM Integration: PR/MR security review, kept separate from Code Scanning.

Code Scanning (`plaidnox_sast`) remains an immutable-snapshot analysis API
with no provider-specific orchestration. This package imports it as a
library and owns everything SCM/PR-specific: diffing, the deterministic
ChangeRelevance gate, base-bound ApplicationContext, changed-file L1 review,
and independent verification. Provider webhooks and publication remain
separate follow-on work.
"""
