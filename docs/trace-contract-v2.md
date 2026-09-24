# Evidence Trace Contract v2

Verified findings may include a provider-neutral vulnerable snippet plus a branching `taint_and_trust` graph. Nodes are validated against the immutable head snapshot and carry source location, structural symbol, source expression, evidence role/kind, label, summary, and provenance. Edges are emitted only when the structural graph, a shared structural anchor, or an explicitly attached route middleware/control supports the transition; otherwise the trace is marked incomplete and records an evidence gap.

Provider adapters render repository links from provider/repository/head/path/line metadata rather than storing GitHub URLs in the scanner result.
