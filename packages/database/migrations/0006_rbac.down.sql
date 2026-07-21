BEGIN;
DROP POLICY IF EXISTS tenant_isolation ON project_role_overrides;
ALTER TABLE project_role_overrides NO FORCE ROW LEVEL SECURITY;
ALTER TABLE project_role_overrides DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS project_role_overrides;
COMMIT;
