-- ============================================================
-- V11: make the RLS policy tolerate an unset current user
-- ============================================================
--
-- The policy cast current_setting('app.current_user_id', true) straight to uuid. That is
-- safe when the setting has never been touched (current_setting returns NULL, and
-- NULL::uuid is NULL, which matches no assignment and correctly returns no rows).
--
-- It is NOT safe on a pooled connection. set_config(..., is_local => true) reverts at the
-- end of the transaction, but a custom GUC that has been set once continues to exist on
-- the session and reverts to the EMPTY STRING rather than to NULL. Any later transaction
-- on that same pooled connection which does not re-bind the user therefore evaluates
-- ''::uuid, and PostgreSQL raises:
--
--   ERROR: invalid input syntax for type uuid: ""
--
-- So instead of denying access, the query failed outright with a 500 — and it only
-- happened after a connection had served at least one bound request, which makes it look
-- intermittent.
--
-- NULLIF maps the empty string back to NULL, restoring the intended fail-closed
-- behaviour: no bound user means no visible rows.
DROP POLICY IF EXISTS case_person_policy ON case_person;

CREATE POLICY case_person_policy ON case_person
    USING (
        EXISTS (
            SELECT 1 FROM case_assignment ca
            WHERE ca.case_id = case_person.case_id
              AND ca.user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
              AND ca.revoked_at IS NULL
        )
    );
