-- ============================================================
-- V14: Retire the legacy nyayavault_app role
--
-- The project was renamed from NyayaVault to CrimeNet. That rename was first applied by
-- editing V1, V2, V4, V9 and V12 in place. Those migrations had already run on existing
-- databases, and Flyway checksums every applied migration: rewriting them makes any
-- database that ran the original versions refuse to start. It also broke V13 on fresh
-- databases, which grants to nyayavault_app — a role the edited V9 no longer created.
--
-- Applied migrations are immutable. The rename is carried out here instead, as a new
-- step every database runs exactly once. crimenet_app, which the application actually
-- connects as, was created alongside nyayavault_app in V9 and is unaffected.
-- ============================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nyayavault_app') THEN
        -- Revokes every privilege and default-privilege entry the role holds in this
        -- database and on shared objects, and drops anything it owns here. Nothing should
        -- be owned by it — it only ever received grants.
        EXECUTE 'DROP OWNED BY nyayavault_app';
        BEGIN
            EXECUTE 'DROP ROLE nyayavault_app';
            RAISE NOTICE 'Retired legacy role nyayavault_app';
        EXCEPTION WHEN dependent_objects_still_exist THEN
            -- Something in another database on this cluster still depends on the role.
            -- Its privileges here are already revoked, so it can no longer touch CrimeNet
            -- data; leaving the empty role behind is not worth failing startup over.
            RAISE NOTICE 'nyayavault_app still has dependents in another database; privileges in this database revoked, role left in place';
        END;
    END IF;
END
$$;
