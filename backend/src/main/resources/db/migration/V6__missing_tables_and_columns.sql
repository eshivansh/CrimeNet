-- ============================================================
-- V6: create the tables and columns the entities require
-- ============================================================
--
-- Nine @Entity classes had no table in V1, and four existing tables drifted from the
-- entities that map them. Because spring.jpa.hibernate.ddl-auto is `validate`, every one
-- of these stops the application from starting. This migration reconciles the schema with
-- the entity model; column names below are taken from the @Column annotations.

-- ── break_glass_grant (BreakGlassService: emergency access grants) ──
CREATE TABLE IF NOT EXISTS break_glass_grant (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES case_record(id),
    granted_to UUID NOT NULL REFERENCES app_user(id),
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',          -- ACTIVE | EXPIRED | REVOKED
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    supervisor_id UUID REFERENCES app_user(id),
    supervisor_notified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bgg_user_case ON break_glass_grant(granted_to, case_id);
CREATE INDEX IF NOT EXISTS idx_bgg_active ON break_glass_grant(status, expires_at);

-- ── security_event (policy denials, anomalies, break-glass signals) ──
CREATE TABLE IF NOT EXISTS security_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    actor_id UUID,
    case_id UUID,
    resource_id UUID,
    severity TEXT NOT NULL DEFAULT 'MEDIUM',        -- LOW | MEDIUM | HIGH | CRITICAL
    description TEXT NOT NULL,
    ip_address TEXT,
    resolved BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_secevent_type ON security_event(event_type);
CREATE INDEX IF NOT EXISTS idx_secevent_severity ON security_event(severity, resolved);

-- ── merkle_batch (AnchorService: Merkle batching of audit events) ──
CREATE TABLE IF NOT EXISTS merkle_batch (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_number BIGINT NOT NULL UNIQUE,
    merkle_root TEXT NOT NULL,
    event_count INT NOT NULL,
    first_event_id UUID NOT NULL,
    last_event_id UUID NOT NULL,
    event_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
    anchor_status TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING | ANCHORED | FAILED
    anchor_type TEXT,                               -- TSA | LEDGER | MOCK
    anchor_reference TEXT,
    anchor_timestamp TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_merkle_status ON merkle_batch(anchor_status);

-- ── idempotency_record (DocumentService: Idempotency-Key replay protection) ──
-- Keyed by the client-supplied header value, so the primary key is text, not a UUID.
CREATE TABLE IF NOT EXISTS idempotency_record (
    idempotency_key TEXT PRIMARY KEY,
    resource_id TEXT,
    status_code INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── policy (versioned ABAC rule definitions) ──
CREATE TABLE IF NOT EXISTS policy (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organization(id),
    policy_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    action TEXT NOT NULL,
    condition_expression TEXT,
    effect TEXT NOT NULL DEFAULT 'ALLOW',           -- ALLOW | DENY
    priority INT DEFAULT 0,
    version INT NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE',          -- ACTIVE | DEPRECATED
    created_by UUID NOT NULL REFERENCES app_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_policy_lookup ON policy(org_id, resource_type, action, status);

-- ── retention_policy (retention and archival schedules per document type) ──
CREATE TABLE IF NOT EXISTS retention_policy (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organization(id),
    doc_type TEXT NOT NULL,
    retention_years INT NOT NULL,
    archive_after_years INT NOT NULL,
    requires_approval_for_disposition BOOLEAN NOT NULL DEFAULT true,
    status TEXT NOT NULL DEFAULT 'ACTIVE',          -- ACTIVE | INACTIVE
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_retpolicy_org_type ON retention_policy(org_id, doc_type);

-- ── digital_signature (signatures over document versions) ──
CREATE TABLE IF NOT EXISTS digital_signature (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_version_id UUID NOT NULL REFERENCES document_version(id),
    signer_id UUID NOT NULL REFERENCES app_user(id),
    signature_value TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'SHA256withRSA',
    certificate_serial TEXT,
    signed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'VALID',           -- VALID | REVOKED
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_digsig_version ON digital_signature(document_version_id);

-- ── workflow_transition (WorkflowService: state transition history) ──
CREATE TABLE IF NOT EXISTS workflow_transition (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type TEXT NOT NULL,                    -- CASE | DOCUMENT | EVIDENCE
    resource_id UUID NOT NULL,
    case_id UUID NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    transitioned_by UUID NOT NULL REFERENCES app_user(id),
    transitioned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason TEXT,
    approval_required BOOLEAN DEFAULT false,
    approved_by UUID REFERENCES app_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_wft_resource ON workflow_transition(resource_type, resource_id);

-- ── sync_job (IntegrationGatewayService: external sync runs) ──
CREATE TABLE IF NOT EXISTS sync_job (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_system TEXT NOT NULL,
    job_type TEXT NOT NULL,                         -- FULL_SYNC | INCREMENTAL | SINGLE_RESOURCE
    status TEXT NOT NULL DEFAULT 'PENDING',
    records_processed INT DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    triggered_by UUID REFERENCES app_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_syncjob_system ON sync_job(source_system, status);

-- ============================================================
-- Columns the entities expect on existing tables
-- ============================================================

-- AIJob maps query_text; V1 created the column as input_query.
ALTER TABLE ai_job ADD COLUMN IF NOT EXISTS query_text TEXT;

-- AIResult maps confidence_score; V1 created it as confidence.
ALTER TABLE ai_result ADD COLUMN IF NOT EXISTS confidence_score DOUBLE PRECISION;

-- AIReference maps chunk_text; V1 created it as chunk_reference.
ALTER TABLE ai_reference ADD COLUMN IF NOT EXISTS chunk_text TEXT;

-- ExternalReference maps source_system / local_resource_id / sync_status.
ALTER TABLE external_reference ADD COLUMN IF NOT EXISTS source_system TEXT;
ALTER TABLE external_reference ADD COLUMN IF NOT EXISTS local_resource_id UUID;
ALTER TABLE external_reference ADD COLUMN IF NOT EXISTS sync_status TEXT DEFAULT 'SYNCED';

-- The entity never populates integration_source_id or resource_id, so leaving them
-- NOT NULL would make every insert fail. Relax them; the entity's own source_system and
-- local_resource_id carry that information instead.
ALTER TABLE external_reference ALTER COLUMN integration_source_id DROP NOT NULL;
ALTER TABLE external_reference ALTER COLUMN resource_id DROP NOT NULL;
