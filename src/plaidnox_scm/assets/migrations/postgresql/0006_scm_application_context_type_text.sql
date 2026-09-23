-- application_type stores the AI-generated architecture narrative
-- (plaidnox_sast's `architecture` field, schema'd up to 8000 characters),
-- not a short label. VARCHAR(128) truncated the very first real narrative
-- this environment ever produced, failing every context save.
ALTER TABLE scm_application_contexts
    ALTER COLUMN application_type TYPE TEXT;
