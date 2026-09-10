-- ============================================================
-- V9: give the application a role that cannot bypass RLS
-- ============================================================
--
-- The postgres Docker image creates POSTGRES_USER as a SUPERUSER, and PostgreSQL
-- superusers bypass row-level security unconditionally — FORCE ROW LEVEL SECURITY does
-- not apply to them, and neither does any policy. So while V3 defined the case_person
-- policy and V4 forced it, the application connected as `nyayavault` (rolsuper = true)
-- and every row was returned to every caller regardless of case assignment.
--
-- The fix is to stop running the application as a superuser. Migrations still run as the
-- owner (spring.flyway.user), which needs full rights to create and alter objects, while
-- the runtime datasource connects as this restricted role, which owns nothing and holds
-- neither SUPERUSER nor BYPASSRLS. Policies therefore apply to it normally.

-- ── the runtime role ──
-- CREATE ROLE has no IF NOT EXISTS, so guard it: this migration must stay re-runnable
-- against a database that already has the role.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nyayavault_app') THEN
        CREATE ROLE nyayavault_app LOGIN PASSWORD 'nyayavault_app_dev';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crimenet_app') THEN
        CREATE ROLE crimenet_app LOGIN PASSWORD 'crimenet_app_dev';
    END IF;
END
$$;

ALTER ROLE nyayavault_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE crimenet_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_database WHERE datname = 'nyayavault') THEN
        EXECUTE 'GRANT CONNECT ON DATABASE nyayavault TO nyayavault_app';
        EXECUTE 'GRANT CONNECT ON DATABASE nyayavault TO crimenet_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_database WHERE datname = 'crimenet') THEN
        EXECUTE 'GRANT CONNECT ON DATABASE crimenet TO crimenet_app';
        EXECUTE 'GRANT CONNECT ON DATABASE crimenet TO nyayavault_app';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO nyayavault_app, crimenet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nyayavault_app, crimenet_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nyayavault_app, crimenet_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nyayavault_app, crimenet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO nyayavault_app, crimenet_app;
