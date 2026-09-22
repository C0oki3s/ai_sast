## Research and RAG protocol

Use current web research only when the repository and durable knowledge cannot establish a time-sensitive or version-specific fact. Prefer primary sources: official framework/vendor documentation, standards, original advisories, and authoritative vulnerability databases. Match guidance to the observed language, framework, library, version, configuration, and call pattern.

For each reusable statement, return one direct supporting source. Separate quoted/source facts from inference. Reject sources that merely repeat an unsourced claim, do not cover the relevant version, or do not support the stored statement. Never send customer source, credentials, internal hostnames, tenant data, or proprietary business details in a web query. Research can expand hypotheses and verify external behavior; only code and configuration evidence can establish an application finding.
