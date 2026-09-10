-- ============================================================
-- V4: RLS hardening + missing AI permission
-- ============================================================

-- ── 1. Make the V3 row-level security policy actually apply ──
-- PostgreSQL exempts a table's OWNER from row-level security unless the table is
-- explicitly FORCEd. Flyway creates case_person as the `nyayavault` role, and the
-- application connects with that same role, so it owned the table and the V3
-- policy was silently bypassed on every query. FORCE closes that gap.
ALTER TABLE case_person FORCE ROW LEVEL SECURITY;

-- ── 2. Recreate the policy so revoked assignments lose access ──
-- The V3 policy matched any row in case_assignment, including assignments that had
-- been revoked (revoked_at IS NOT NULL). An officer removed from a case could still
-- read its PII. Everything else about the policy is unchanged.
DROP POLICY IF EXISTS case_person_policy ON case_person;

CREATE POLICY case_person_policy ON case_person
    USING (
        EXISTS (
            SELECT 1 FROM case_assignment ca
            WHERE ca.case_id = case_person.case_id
              AND ca.user_id = current_setting('app.current_user_id', true)::uuid
              AND ca.revoked_at IS NULL
        )
    );

-- ── 3. Grant the AI/QUERY permission ──
-- AIService calls enforceCasePermission(caseId, "AI", "QUERY"), but no role was ever
-- granted an 'AI' resource permission. Only ADMIN (which short-circuits the check)
-- could run an AI query; every other role failed with AccessDeniedException.
INSERT INTO permission (role_id, resource, action) VALUES
    ('00000000-0000-0000-0002-000000000001', 'AI', 'QUERY'),  -- ADMIN
    ('00000000-0000-0000-0002-000000000002', 'AI', 'QUERY'),  -- INVESTIGATOR
    ('00000000-0000-0000-0002-000000000003', 'AI', 'QUERY'),  -- SUPERVISOR
    ('00000000-0000-0000-0002-000000000005', 'AI', 'QUERY')   -- PROSECUTOR
ON CONFLICT (role_id, resource, action) DO NOTHING;
