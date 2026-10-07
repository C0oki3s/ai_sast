-- Pull request metadata for the dashboard (branch, base, full name, author).
-- Nullable: rows written before this migration, and requests from bots that do
-- not send `author_login`, simply leave them empty.
ALTER TABLE scm_review_attempts ADD COLUMN IF NOT EXISTS base_ref VARCHAR(255);
ALTER TABLE scm_review_attempts ADD COLUMN IF NOT EXISTS head_ref VARCHAR(255);
ALTER TABLE scm_review_attempts ADD COLUMN IF NOT EXISTS repository_full_name VARCHAR(255);
ALTER TABLE scm_review_attempts ADD COLUMN IF NOT EXISTS author_login VARCHAR(255);
