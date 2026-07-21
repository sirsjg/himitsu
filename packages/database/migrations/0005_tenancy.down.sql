BEGIN;

DO $tenancy$
DECLARE
  tenant_table text;
BEGIN
  FOREACH tenant_table IN ARRAY ARRAY[
    'projects', 'environments', 'secrets', 'secret_versions', 'tags', 'secret_tags',
    'api_keys', 'audit_events', 'org_encryption_keys', 'organization_invitations'
  ]
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', tenant_table);
    EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', tenant_table);
  END LOOP;
END
$tenancy$;

DROP POLICY IF EXISTS memberships_delete ON memberships;
DROP POLICY IF EXISTS memberships_update ON memberships;
DROP POLICY IF EXISTS memberships_insert ON memberships;
DROP POLICY IF EXISTS memberships_read ON memberships;
ALTER TABLE memberships NO FORCE ROW LEVEL SECURITY;
ALTER TABLE memberships DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS organizations_delete ON organizations;
DROP POLICY IF EXISTS organizations_update ON organizations;
DROP POLICY IF EXISTS organizations_insert ON organizations;
DROP POLICY IF EXISTS organizations_read ON organizations;
ALTER TABLE organizations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE organizations DISABLE ROW LEVEL SECURITY;

DROP FUNCTION IF EXISTS resolve_invitation_org(bytea);
DROP FUNCTION IF EXISTS app_membership_discovery_enabled();
DROP FUNCTION IF EXISTS app_current_user_id();
DROP FUNCTION IF EXISTS app_current_org_id();

DROP INDEX IF EXISTS sessions_user_active_org_idx;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_active_membership_fk;
ALTER TABLE sessions DROP COLUMN IF EXISTS active_org_id;
DROP TABLE IF EXISTS organization_invitations;

COMMIT;
