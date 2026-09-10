-- ============================================================
-- V5: add document.is_archived
-- ============================================================

-- The Document entity maps a non-null `is_archived` column and RetentionService both
-- reads it (doc.isArchived()) and writes it (doc.setArchived(true)) when archiving a
-- document, but the column was never created in V1. With spring.jpa.hibernate.ddl-auto
-- set to `validate`, the missing column fails schema validation and the application
-- refuses to start.
ALTER TABLE document
    ADD COLUMN IF NOT EXISTS is_archived BOOLEAN NOT NULL DEFAULT false;

-- Archival sweeps and retention queries filter on this flag.
CREATE INDEX IF NOT EXISTS idx_document_archived ON document(is_archived);
