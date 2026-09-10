-- ============================================================
-- V7: add the created_at column BaseEntity requires
-- ============================================================
--
-- Every entity extending BaseEntity inherits a non-null `created_at` mapping, but six
-- tables were created in V1 with a domain-specific timestamp (assigned_at, synced_at,
-- applied_at, accessed_at) and no created_at at all. Hibernate schema validation fails
-- on the first of them and the application will not start.

ALTER TABLE case_assignment    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE external_reference ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE legal_hold         ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE permission         ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE share_access       ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE user_role          ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Where the table already carried a meaningful creation timestamp, keep the two in step
-- rather than stamping pre-existing rows with the migration time.
--
-- share_access is deliberately excluded: it is one of the append-only tables guarded by a
-- trigger that rejects UPDATE, so backfilling it would abort this migration. Its rows keep
-- the DEFAULT above, and accessed_at remains the authoritative access time.
-- permission is excluded as well, having never had a timestamp to copy from.
UPDATE case_assignment    SET created_at = assigned_at WHERE created_at <> assigned_at;
UPDATE external_reference SET created_at = synced_at   WHERE created_at <> synced_at;
UPDATE legal_hold         SET created_at = applied_at  WHERE created_at <> applied_at;
UPDATE user_role          SET created_at = assigned_at WHERE created_at <> assigned_at;
