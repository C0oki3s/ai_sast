# Code Scanning acceptance gate

Phase 5 release evidence is produced from immutable scan reports, not from a
special scanner mode. Copy `acceptance/manifest.example.json`, list each seeded
positive and clean control, and keep reports below the manifest directory.
Expected findings are matched by repository-relative path, optional
vulnerability class, and optional overlapping line range.

Run the evaluator after the scans finish:

```bash
plaidnox-sast evaluate-acceptance acceptance/manifest.json \
  --output acceptance/result.json
```

The command exits with status 2 when recall, precision, duplicate rate, or
scan-completeness thresholds fail. The result also aggregates prompt-cache
tokens, model input/output tokens, and reported model cost.

The production release set must contain:

- `C0oki3s/NSTCTF` at a pinned commit, with reviewed expectations;
- multi-language seeded positives, root-cause variants, and clean controls;
- hostile instruction strings in source comments and documentation;
- redaction fixtures containing synthetic credentials;
- malformed LiteLLM responses and LiteLLM outage simulation;
- stale research entries and unavailable research-gateway cases;
- worker termination after lease acquisition followed by lease recovery;
- PostgreSQL backup, restore, migration replay, and checksum mismatch cases.

Run each target more than once. Compare finding fingerprints, decisions,
coverage completion, context reuse, cache-token reuse, duration, token usage,
and cost. A human security reviewer must validate the expectation set and every
unexpected finding before changing thresholds. The evaluator never labels a
code path vulnerable by itself; it only scores completed Deep Hunt reports.

No acceptance target is scanned automatically by tests, image builds,
migrations, or worker startup.
