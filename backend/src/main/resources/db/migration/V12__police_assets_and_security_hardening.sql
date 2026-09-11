-- ============================================================
-- V12: Police Asset Management, Digital Signatures & Security Hardening
-- ============================================================

-- ── 1. Police Asset Table ──
CREATE TABLE IF NOT EXISTS police_asset (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES case_record(id) ON DELETE SET NULL,
    asset_tag VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'AVAILABLE',
    custodian_id UUID REFERENCES app_user(id) ON DELETE SET NULL,
    custodian_badge VARCHAR(64),
    department VARCHAR(128),
    assigned_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_police_asset_case ON police_asset(case_id);
CREATE INDEX IF NOT EXISTS idx_police_asset_custodian ON police_asset(custodian_id);
CREATE INDEX IF NOT EXISTS idx_police_asset_status ON police_asset(status);

-- ── 2. Document Digital Signature Table ──
CREATE TABLE IF NOT EXISTS document_signature (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES document(id) ON DELETE CASCADE,
    version_id UUID REFERENCES document_version(id) ON DELETE CASCADE,
    signer_id UUID NOT NULL REFERENCES app_user(id),
    signer_name VARCHAR(255) NOT NULL,
    signer_role VARCHAR(64) NOT NULL,
    signature_algorithm VARCHAR(64) NOT NULL DEFAULT 'SHA256withRSA',
    signature_value TEXT NOT NULL,
    public_key_cert TEXT NOT NULL,
    document_hash VARCHAR(64) NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified BOOLEAN NOT NULL DEFAULT true,
    revoked BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_doc_signature_doc ON document_signature(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_signature_signer ON document_signature(signer_id);

-- ── 3. Asset & Signature Permissions ──
INSERT INTO permission (role_id, resource, action) VALUES
    ('00000000-0000-0000-0002-000000000001', 'ASSET', 'MANAGE'),
    ('00000000-0000-0000-0002-000000000001', 'DOCUMENT', 'SIGN'),
    ('00000000-0000-0000-0002-000000000001', 'DOCUMENT', 'VERIFY'),
    
    ('00000000-0000-0000-0002-000000000002', 'ASSET', 'READ'),
    ('00000000-0000-0000-0002-000000000002', 'ASSET', 'UPDATE'),
    ('00000000-0000-0000-0002-000000000002', 'DOCUMENT', 'SIGN'),
    ('00000000-0000-0000-0002-000000000002', 'DOCUMENT', 'VERIFY'),

    ('00000000-0000-0000-0002-000000000003', 'ASSET', 'MANAGE'),
    ('00000000-0000-0000-0002-000000000003', 'ASSET', 'READ'),
    ('00000000-0000-0000-0002-000000000003', 'ASSET', 'ASSIGN'),
    ('00000000-0000-0000-0002-000000000003', 'DOCUMENT', 'SIGN'),
    ('00000000-0000-0000-0002-000000000003', 'DOCUMENT', 'VERIFY'),

    ('00000000-0000-0000-0002-000000000004', 'ASSET', 'READ'),
    ('00000000-0000-0000-0002-000000000004', 'DOCUMENT', 'SIGN'),
    ('00000000-0000-0000-0002-000000000004', 'DOCUMENT', 'VERIFY'),

    ('00000000-0000-0000-0002-000000000005', 'DOCUMENT', 'VERIFY'),
    ('00000000-0000-0000-0002-000000000006', 'ASSET', 'READ'),
    ('00000000-0000-0000-0002-000000000006', 'DOCUMENT', 'VERIFY')
ON CONFLICT (role_id, resource, action) DO NOTHING;

-- ── 4. Grants for runtime app role ──
GRANT SELECT, INSERT, UPDATE, DELETE ON police_asset TO crimenet_app, crimenet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON document_signature TO crimenet_app, crimenet_app;
