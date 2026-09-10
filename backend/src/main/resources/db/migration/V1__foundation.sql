-- ============================================================
-- NyayaVault Foundation Schema
-- V1: Core tables, indexes, append-only triggers
-- ============================================================

-- ── Organization & Identity ──

CREATE TABLE organization (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE department (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organization(id),
    name TEXT NOT NULL,
    code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, code)
);
CREATE INDEX idx_department_org ON department(org_id);

CREATE TABLE app_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organization(id),
    keycloak_subject TEXT NOT NULL UNIQUE,
    department_id UUID REFERENCES department(id),
    display_name TEXT NOT NULL,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_user_org ON app_user(org_id);
CREATE INDEX idx_user_department ON app_user(department_id);
CREATE INDEX idx_user_keycloak ON app_user(keycloak_subject);

-- ── Roles & Permissions ──

CREATE TABLE role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permission (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    UNIQUE(role_id, resource, action)
);
CREATE INDEX idx_permission_role ON permission(role_id);

CREATE TABLE user_role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, role_id)
);
CREATE INDEX idx_userrole_user ON user_role(user_id);

-- ── Case ──

CREATE TABLE case_record (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organization(id),
    case_number TEXT NOT NULL UNIQUE,
    title TEXT,
    description TEXT,
    fir_id TEXT,
    icjs_case_id TEXT,
    classification TEXT NOT NULL DEFAULT 'STANDARD',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_by UUID NOT NULL REFERENCES app_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_case_org_status ON case_record(org_id, status);
CREATE INDEX idx_case_classification ON case_record(classification);
CREATE INDEX idx_case_created_by ON case_record(created_by);

CREATE TABLE case_assignment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES case_record(id),
    user_id UUID NOT NULL REFERENCES app_user(id),
    role_in_case TEXT NOT NULL,
    assigned_by UUID REFERENCES app_user(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE(case_id, user_id, role_in_case)
);
CREATE INDEX idx_assignment_user ON case_assignment(user_id);
CREATE INDEX idx_assignment_case ON case_assignment(case_id);
CREATE INDEX idx_assignment_active ON case_assignment(case_id, user_id) WHERE revoked_at IS NULL;

CREATE TABLE case_person (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES case_record(id),
    person_name TEXT NOT NULL,
    role_type TEXT NOT NULL,          -- VICTIM | WITNESS | ACCUSED | INFORMANT
    id_type TEXT,                      -- AADHAAR | PAN | PASSPORT | OTHER
    id_number_encrypted TEXT,          -- encrypted PII
    contact_encrypted TEXT,            -- encrypted PII
    address_encrypted TEXT,            -- encrypted PII
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_by UUID NOT NULL REFERENCES app_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_caseperson_case ON case_person(case_id);
CREATE INDEX idx_caseperson_role ON case_person(role_type);

-- ── Document ──

CREATE TABLE document (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES case_record(id),
    org_id UUID NOT NULL REFERENCES organization(id),
    business_id TEXT NOT NULL UNIQUE,
    doc_type TEXT NOT NULL,
    title TEXT,
    classification TEXT NOT NULL DEFAULT 'STANDARD',
    current_version_id UUID,            -- set after first version is created
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_by UUID NOT NULL REFERENCES app_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_document_case ON document(case_id);
CREATE INDEX idx_document_org ON document(org_id);
CREATE INDEX idx_document_status ON document(status);
CREATE INDEX idx_document_type ON document(doc_type);

CREATE TABLE document_version (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES document(id),
    version_no INT NOT NULL,
    content_hash TEXT NOT NULL,
    object_key TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    mime_type TEXT NOT NULL,
    upload_status TEXT NOT NULL DEFAULT 'PENDING',   -- PENDING | COMMITTED | FAILED
    created_by UUID NOT NULL REFERENCES app_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(document_id, version_no)
);
CREATE INDEX idx_docversion_document ON document_version(document_id);
CREATE INDEX idx_docversion_hash ON document_version(content_hash);
CREATE INDEX idx_docversion_status ON document_version(upload_status);

CREATE TABLE document_classification (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES document(id),
    tag TEXT NOT NULL,
    assigned_by UUID REFERENCES app_user(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(document_id, tag)
);
CREATE INDEX idx_docclass_document ON document_classification(document_id);

-- ── Evidence & Custody ──

CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES case_record(id),
    org_id UUID NOT NULL REFERENCES organization(id),
    evidence_code TEXT NOT NULL UNIQUE,
    title TEXT,
    description TEXT,
    source TEXT NOT NULL,
    source_device TEXT,
    collected_by UUID NOT NULL REFERENCES app_user(id),
    collected_at TIMESTAMPTZ NOT NULL,
    location TEXT,
    initial_hash TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'STANDARD',
    status TEXT NOT NULL DEFAULT 'REGISTERED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_evidence_case ON evidence(case_id);
CREATE INDEX idx_evidence_org ON evidence(org_id);

CREATE TABLE evidence_artifact (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    artifact_type TEXT NOT NULL,        -- PHOTO | VIDEO | AUDIO | BINARY | DOCUMENT
    object_key TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    mime_type TEXT,
    description TEXT,
    created_by UUID NOT NULL REFERENCES app_user(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_artifact_evidence ON evidence_artifact(evidence_id);

CREATE TABLE custody_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    artifact_id UUID REFERENCES evidence_artifact(id),
    from_actor UUID REFERENCES app_user(id),
    to_actor UUID NOT NULL REFERENCES app_user(id),
    action TEXT NOT NULL,               -- REGISTERED | TRANSFERRED | ANALYZED | STORED | PRESENTED | RETURNED | DISPOSED
    purpose TEXT,
    location TEXT,
    notes TEXT,
    event_hash TEXT NOT NULL,
    previous_event_id UUID REFERENCES custody_event(id),
    previous_event_hash TEXT,
    signature TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_custody_evidence_time ON custody_event(evidence_id, created_at);
CREATE INDEX idx_custody_previous ON custody_event(previous_event_id);

-- ── Audit ──

CREATE TABLE audit_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    actor_id UUID REFERENCES app_user(id),
    resource_type TEXT,
    resource_id UUID,
    case_id UUID REFERENCES case_record(id),
    org_id UUID REFERENCES organization(id),
    ip_address TEXT,
    user_agent TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload_hash TEXT NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_case_time ON audit_event(case_id, created_at);
CREATE INDEX idx_audit_type_time ON audit_event(event_type, created_at);
CREATE INDEX idx_audit_actor ON audit_event(actor_id);
CREATE INDEX idx_audit_resource ON audit_event(resource_type, resource_id);

-- ── Sharing ──

CREATE TABLE share_package (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES case_record(id),
    created_by UUID NOT NULL REFERENCES app_user(id),
    recipient_id UUID REFERENCES app_user(id),
    recipient_email TEXT,
    purpose TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,   -- list of document/evidence IDs
    rights TEXT NOT NULL DEFAULT 'VIEW_ONLY',    -- VIEW_ONLY | VIEW_DOWNLOAD | VIEW_PRINT
    watermark_enabled BOOLEAN NOT NULL DEFAULT true,
    mfa_required BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',        -- ACTIVE | EXPIRED | REVOKED
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_share_case ON share_package(case_id);
CREATE INDEX idx_share_recipient ON share_package(recipient_id);
CREATE INDEX idx_share_status ON share_package(status);

CREATE TABLE share_access (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    share_package_id UUID NOT NULL REFERENCES share_package(id),
    accessed_by UUID NOT NULL REFERENCES app_user(id),
    action TEXT NOT NULL,                -- VIEWED | DOWNLOADED | PRINTED
    resource_id UUID,
    ip_address TEXT,
    user_agent TEXT,
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_shareaccess_package ON share_access(share_package_id);

-- ── Retention & Legal Hold ──

CREATE TABLE legal_hold (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES case_record(id),
    reason TEXT NOT NULL,
    applied_by UUID NOT NULL REFERENCES app_user(id),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_by UUID REFERENCES app_user(id),
    released_at TIMESTAMPTZ,
    release_reason TEXT
);
CREATE INDEX idx_legalhold_case_active ON legal_hold(case_id) WHERE released_at IS NULL;

-- ── Integration ──

CREATE TABLE integration_source (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    system_name TEXT NOT NULL UNIQUE,    -- ICJS | CCTNS | ESAKSHYA | EOFFICE | ECOURTS
    base_url TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE external_reference (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_source_id UUID NOT NULL REFERENCES integration_source(id),
    external_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,          -- CASE | DOCUMENT | EVIDENCE
    resource_id UUID NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(integration_source_id, external_id, resource_type)
);
CREATE INDEX idx_extref_resource ON external_reference(resource_type, resource_id);

-- ── AI Provenance (structure only, Phase 8) ──

CREATE TABLE ai_job (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type TEXT NOT NULL,              -- QUERY | CLASSIFY | SUMMARIZE | EXTRACT
    requested_by UUID NOT NULL REFERENCES app_user(id),
    case_id UUID REFERENCES case_record(id),
    input_query TEXT,
    model_name TEXT,
    model_version TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE ai_result (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL UNIQUE REFERENCES ai_job(id),
    response_text TEXT,
    confidence DOUBLE PRECISION,
    token_count INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_reference (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    result_id UUID NOT NULL REFERENCES ai_result(id),
    document_id UUID REFERENCES document(id),
    document_version_id UUID REFERENCES document_version(id),
    chunk_reference TEXT,
    relevance_score DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_airef_result ON ai_reference(result_id);

-- ============================================================
-- APPEND-ONLY TRIGGERS
-- Prevents UPDATE and DELETE on immutable tables
-- ============================================================

CREATE OR REPLACE FUNCTION reject_update_delete() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Table % is append-only. UPDATE and DELETE operations are prohibited.', TG_TABLE_NAME;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Document versions: immutable once created
CREATE TRIGGER document_version_no_update
    BEFORE UPDATE OR DELETE ON document_version
    FOR EACH ROW
    WHEN (OLD.upload_status = 'COMMITTED')
    EXECUTE FUNCTION reject_update_delete();

-- Allow status transition from PENDING to COMMITTED/FAILED only
CREATE OR REPLACE FUNCTION allow_docversion_status_transition() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.upload_status = 'PENDING' AND NEW.upload_status IN ('COMMITTED', 'FAILED') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'Invalid document_version status transition from % to %', OLD.upload_status, NEW.upload_status;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER document_version_status_transition
    BEFORE UPDATE ON document_version
    FOR EACH ROW
    EXECUTE FUNCTION allow_docversion_status_transition();

-- Custody events: append-only
CREATE TRIGGER custody_event_no_update
    BEFORE UPDATE OR DELETE ON custody_event
    FOR EACH ROW
    EXECUTE FUNCTION reject_update_delete();

-- Audit events: append-only
CREATE TRIGGER audit_event_no_update
    BEFORE UPDATE OR DELETE ON audit_event
    FOR EACH ROW
    EXECUTE FUNCTION reject_update_delete();

-- Share access log: append-only
CREATE TRIGGER share_access_no_update
    BEFORE UPDATE OR DELETE ON share_access
    FOR EACH ROW
    EXECUTE FUNCTION reject_update_delete();
