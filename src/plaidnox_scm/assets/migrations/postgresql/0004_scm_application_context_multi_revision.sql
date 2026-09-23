-- Two concurrently open PRs against different base commits must not
-- overwrite each other's cached ApplicationContext row. Widen the primary
-- key to include baseline_revision so both coexist.
ALTER TABLE scm_application_contexts
    DROP CONSTRAINT scm_application_contexts_pkey;

ALTER TABLE scm_application_contexts
    ADD PRIMARY KEY (tenant_id, codebase_id, baseline_revision);
