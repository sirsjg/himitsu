BEGIN;

CREATE TABLE organization_invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email text NOT NULL CHECK (length(btrim(email)) BETWEEN 3 AND 320),
  email_normalized text GENERATED ALWAYS AS (lower(btrim(email))) STORED,
  role organization_role NOT NULL CHECK (role <> 'owner'),
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  invited_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz,
  accepted_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  revoked_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK (accepted_at IS NULL OR accepted_by_user_id IS NOT NULL),
  UNIQUE (org_id, id)
);

CREATE UNIQUE INDEX organization_invitations_pending_email_idx
  ON organization_invitations (org_id, email_normalized)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

ALTER TABLE sessions ADD COLUMN active_org_id uuid;
ALTER TABLE sessions ADD CONSTRAINT sessions_active_membership_fk
  FOREIGN KEY (active_org_id, user_id) REFERENCES memberships(org_id, user_id) ON DELETE RESTRICT;
CREATE INDEX sessions_user_active_org_idx ON sessions (user_id, active_org_id)
  WHERE revoked_at IS NULL;

CREATE FUNCTION app_current_org_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT NULLIF(current_setting('app.current_org_id', true), '')::uuid $$;

CREATE FUNCTION app_current_user_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT NULLIF(current_setting('app.current_user_id', true), '')::uuid $$;

CREATE FUNCTION app_membership_discovery_enabled() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT COALESCE(current_setting('app.membership_discovery', true), '') = 'on' $$;

CREATE FUNCTION resolve_invitation_org(invitation_token_hash bytea) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT org_id
  FROM public.organization_invitations
  WHERE token_hash = invitation_token_hash
    AND accepted_at IS NULL
    AND revoked_at IS NULL
    AND expires_at > now()
$$;

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY memberships_read ON memberships FOR SELECT
  USING (
    org_id = app_current_org_id()
    OR (app_membership_discovery_enabled() AND user_id = app_current_user_id())
  );
CREATE POLICY memberships_insert ON memberships FOR INSERT
  WITH CHECK (org_id = app_current_org_id());
CREATE POLICY memberships_update ON memberships FOR UPDATE
  USING (org_id = app_current_org_id()) WITH CHECK (org_id = app_current_org_id());
CREATE POLICY memberships_delete ON memberships FOR DELETE
  USING (org_id = app_current_org_id());

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organizations_read ON organizations FOR SELECT
  USING (
    id = app_current_org_id()
    OR EXISTS (
      SELECT 1 FROM memberships
      WHERE memberships.org_id = organizations.id
        AND memberships.user_id = app_current_user_id()
        AND memberships.status = 'active'
    )
  );
CREATE POLICY organizations_insert ON organizations FOR INSERT
  WITH CHECK (id = app_current_org_id());
CREATE POLICY organizations_update ON organizations FOR UPDATE
  USING (id = app_current_org_id()) WITH CHECK (id = app_current_org_id());
CREATE POLICY organizations_delete ON organizations FOR DELETE
  USING (id = app_current_org_id());

DO $tenancy$
DECLARE
  tenant_table text;
BEGIN
  FOREACH tenant_table IN ARRAY ARRAY[
    'projects', 'environments', 'secrets', 'secret_versions', 'tags', 'secret_tags',
    'api_keys', 'audit_events', 'org_encryption_keys', 'organization_invitations'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (org_id = app_current_org_id()) WITH CHECK (org_id = app_current_org_id())',
      tenant_table
    );
  END LOOP;
END
$tenancy$;

COMMIT;
