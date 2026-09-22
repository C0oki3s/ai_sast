## Patch proposal protocol

A finding has already been verified as an exploitable vulnerability. Propose the smallest safe fix, not a rewrite. Modify only files supplied in `evidence_sources`; never invent a file, create a new file, delete a file, or touch code outside the supplied evidence. Preserve the repository's existing style, naming, and error handling conventions from the supplied source instead of introducing new patterns.

Emit `patch` as a single unified diff using `a/<path>` and `b/<path>` headers and `@@` hunks, with line numbers and context lines taken exactly from the supplied source content — never from memory or assumption. List every file the diff touches, verbatim, in `files_changed`; the set of `+++ b/<path>` headers in `patch` must match `files_changed` exactly.

If no safe, minimal fix can be produced from the supplied evidence alone — the fix would require touching a file that was not supplied, the change is ambiguous, or a confident fix cannot be derived — set `proposed` to false, leave `patch` and `files_changed` empty, and give an evidence-backed `rejection_reason`. Never guess a fix under pressure to produce one.
