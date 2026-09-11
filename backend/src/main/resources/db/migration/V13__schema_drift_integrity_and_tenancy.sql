-- ============================================================
-- V13: Schema drift repair, integrity guards, tenancy and identifier sequences
--
-- 1. document_signature.created_at      — restores startup under ddl-auto: validate
-- 2. Append-only guards on merkle_batch and document_signature
-- 3. police_asset.org_id                — closes cross-tenant asset disclosure
-- 4. Identifier sequences               — replaces racy count()+1 generation
-- 5. Missing indexes for existing query patterns
-- 6. external_reference uniqueness      — declared on the entity, never created
-- ============================================================

-- ── 1. Schema drift: DocumentSignature extends BaseEntity, which maps created_at ──
ALTER TABLE document_signature ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
UPDATE document_signature SET created_at = signed_at WHERE created_at <> signed_at;

-- ── 2. Append-only guards ──
-- merkle_batch was created in V6 without the protection V1 gave the other
-- provenance tables, so the anchor record itself was rewritable.
DROP TRIGGER IF EXISTS merkle_batch_no_delete ON merkle_batch;
CREATE TRIGGER merkle_batch_no_delete
    BEFORE DELETE ON merkle_batch
    FOR EACH ROW
    EXECUTE FUNCTION reject_update_delete();

-- The anchor fields are written once, after the batch row exists. Everything
-- that identifies the batch and its contents is frozen at insert.
CREATE OR REPLACE FUNCTION allow_merkle_batch_anchor_update() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.batch_number  IS DISTINCT FROM OLD.batch_number
       OR NEW.merkle_root IS DISTINCT FROM OLD.merkle_root
       OR NEW.event_count IS DISTINCT FROM OLD.event_count
       OR NEW.event_hashes IS DISTINCT FROM OLD.event_hashes
       OR NEW.first_event_id IS DISTINCT FROM OLD.first_event_id
       OR NEW.last_event_id  IS DISTINCT FROM OLD.last_event_id THEN
        RAISE EXCEPTION 'merkle_batch identity and contents are immutable; only anchor status fields may be updated';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS merkle_batch_contents_immutable ON merkle_batch;
CREATE TRIGGER merkle_batch_contents_immutable
    BEFORE UPDATE ON merkle_batch
    FOR EACH ROW
    EXECUTE FUNCTION allow_merkle_batch_anchor_update();

-- Signatures are evidence: revocation flips one flag, nothing else moves.
CREATE OR REPLACE FUNCTION allow_signature_revocation_only() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.document_id IS DISTINCT FROM OLD.document_id
       OR NEW.version_id IS DISTINCT FROM OLD.version_id
       OR NEW.signer_id IS DISTINCT FROM OLD.signer_id
       OR NEW.signature_value IS DISTINCT FROM OLD.signature_value
       OR NEW.public_key_cert IS DISTINCT FROM OLD.public_key_cert
       OR NEW.document_hash IS DISTINCT FROM OLD.document_hash
       OR NEW.signature_algorithm IS DISTINCT FROM OLD.signature_algorithm
       OR NEW.signed_at IS DISTINCT FROM OLD.signed_at THEN
        RAISE EXCEPTION 'document_signature is immutable except for the revoked flag';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS document_signature_immutable ON document_signature;
CREATE TRIGGER document_signature_immutable
    BEFORE UPDATE ON document_signature
    FOR EACH ROW
    EXECUTE FUNCTION allow_signature_revocation_only();

DROP TRIGGER IF EXISTS document_signature_no_delete ON document_signature;
CREATE TRIGGER document_signature_no_delete
    BEFORE DELETE ON document_signature
    FOR EACH ROW
    EXECUTE FUNCTION reject_update_delete();

-- ── 3. Tenancy for police assets ──
ALTER TABLE police_asset ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organization(id);

-- Backfill: prefer the custodian's organization, then the linked case, then the
-- single seeded organization (correct while all users still resolve to it).
UPDATE police_asset pa
   SET org_id = u.org_id
  FROM app_user u
 WHERE pa.org_id IS NULL AND pa.custodian_id = u.id AND u.org_id IS NOT NULL;

UPDATE police_asset pa
   SET org_id = c.org_id
  FROM case_record c
 WHERE pa.org_id IS NULL AND pa.case_id = c.id AND c.org_id IS NOT NULL;

UPDATE police_asset
   SET org_id = (SELECT id FROM organization ORDER BY created_at LIMIT 1)
 WHERE org_id IS NULL;

ALTER TABLE police_asset ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_police_asset_org ON police_asset(org_id);

-- ── 4. Identifier sequences ──
-- count()+1 raced two concurrent creates into a unique-constraint violation and
-- reused numbers after a rollback. Seed each sequence past the existing maximum.
CREATE SEQUENCE IF NOT EXISTS case_number_seq   AS BIGINT START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS evidence_code_seq AS BIGINT START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE IF NOT EXISTS document_business_seq AS BIGINT START WITH 1 INCREMENT BY 1;

-- Existing identifiers end in the counter (CASE-2026-UP-000042, DOC-UP-2026-000042,
-- E-000042), so the trailing digit group is what the sequence must clear.
SELECT setval('case_number_seq',
              GREATEST((SELECT COALESCE(MAX((regexp_match(case_number, '(\d+)$'))[1]::BIGINT), 0)
                          FROM case_record), 1));
SELECT setval('evidence_code_seq',
              GREATEST((SELECT COALESCE(MAX((regexp_match(evidence_code, '(\d+)$'))[1]::BIGINT), 0)
                          FROM evidence), 1));
SELECT setval('document_business_seq',
              GREATEST((SELECT COALESCE(MAX((regexp_match(business_id, '(\d+)$'))[1]::BIGINT), 0)
                          FROM document), 1));

-- ── 5. Missing indexes ──
-- Every audit write reads the chain head with ORDER BY created_at DESC LIMIT 1,
-- inside a global advisory lock, and nothing supported a bare created_at scan.
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_event(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflow_transition_case ON workflow_transition(case_id);
CREATE INDEX IF NOT EXISTS idx_doc_signature_version ON document_signature(version_id);
CREATE INDEX IF NOT EXISTS idx_police_asset_category ON police_asset(category);
CREATE INDEX IF NOT EXISTS idx_police_asset_created ON police_asset(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secevent_resolved ON security_event(resolved, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_idempotency_created ON idempotency_record(created_at);
CREATE INDEX IF NOT EXISTS idx_docversion_content_hash ON document_version(content_hash);

-- ── 6. external_reference uniqueness ──
-- The entity declares this constraint; no migration ever created it, and V1's
-- composite unique stopped applying when V6 made integration_source_id nullable.
DELETE FROM external_reference a
      USING external_reference b
      WHERE a.ctid < b.ctid
        AND a.source_system IS NOT NULL
        AND a.source_system = b.source_system
        AND a.external_id = b.external_id;

CREATE UNIQUE INDEX IF NOT EXISTS uq_extref_source_external
    ON external_reference(source_system, external_id)
    WHERE source_system IS NOT NULL;

-- ── 7. Grants for the runtime role on the new sequences ──
GRANT USAGE, SELECT ON SEQUENCE case_number_seq, evidence_code_seq, document_business_seq
    TO nyayavault_app, crimenet_app;
