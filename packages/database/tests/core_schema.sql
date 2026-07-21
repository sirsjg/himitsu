\set ON_ERROR_STOP on

DO $test$
DECLARE
  expected_tables text[] := ARRAY[
    'api_keys', 'audit_events', 'environments', 'memberships', 'organizations',
    'projects', 'secret_tags', 'secret_versions', 'secrets', 'tags', 'users'
  ];
  missing_tables text[];
  tenant_tables text[] := ARRAY[
    'memberships', 'projects', 'environments', 'secrets', 'secret_versions',
    'tags', 'secret_tags', 'api_keys', 'audit_events'
  ];
  invalid_org_columns text[];
BEGIN
  SELECT array_agg(name ORDER BY name)
  INTO missing_tables
  FROM unnest(expected_tables) AS name
  WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = name
  );

  IF missing_tables IS NOT NULL THEN
    RAISE EXCEPTION 'missing core tables: %', missing_tables;
  END IF;

  SELECT array_agg(name ORDER BY name)
  INTO invalid_org_columns
  FROM unnest(tenant_tables) AS name
  WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = name
      AND column_name = 'org_id'
      AND is_nullable = 'NO'
  );

  IF invalid_org_columns IS NOT NULL THEN
    RAISE EXCEPTION 'tenant tables missing non-null org_id: %', invalid_org_columns;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'secrets'
      AND indexdef LIKE '%(org_id, project_id, environment_id, key)%'
  ) THEN
    RAISE EXCEPTION 'missing composite secret lookup index';
  END IF;
END
$test$;

BEGIN;

INSERT INTO organizations (id, name, slug) VALUES
  ('10000000-0000-0000-0000-000000000001', 'Alpha', 'alpha'),
  ('20000000-0000-0000-0000-000000000002', 'Beta', 'beta');

INSERT INTO users (id, email) VALUES
  ('30000000-0000-0000-0000-000000000003', 'Owner@Example.com');

INSERT INTO memberships (org_id, user_id, role) VALUES
  ('10000000-0000-0000-0000-000000000001', '30000000-0000-0000-0000-000000000003', 'owner');

INSERT INTO projects (id, org_id, name, slug) VALUES
  ('40000000-0000-0000-0000-000000000004', '10000000-0000-0000-0000-000000000001', 'Application', 'application');

INSERT INTO environments (id, org_id, project_id, name, slug) VALUES
  ('50000000-0000-0000-0000-000000000005', '10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000004', 'Development', 'development'),
  ('50000000-0000-0000-0000-000000000006', '10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000004', 'Production', 'production');

INSERT INTO secrets (id, org_id, project_id, environment_id, key) VALUES
  ('60000000-0000-0000-0000-000000000006', '10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000004', '50000000-0000-0000-0000-000000000005', 'DATABASE_URL');

INSERT INTO secrets (org_id, project_id, environment_id, key) VALUES
  ('10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000004', '50000000-0000-0000-0000-000000000006', 'DATABASE_URL');

DO $test$
BEGIN
  INSERT INTO secrets (org_id, project_id, environment_id, key) VALUES
    ('10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000004', '50000000-0000-0000-0000-000000000005', 'DATABASE_URL');
  RAISE EXCEPTION 'duplicate secret key was accepted';
EXCEPTION
  WHEN unique_violation THEN NULL;
END
$test$;

DO $test$
BEGIN
  INSERT INTO environments (org_id, project_id, name, slug) VALUES
    ('20000000-0000-0000-0000-000000000002', '40000000-0000-0000-0000-000000000004', 'Cross tenant', 'cross-tenant');
  RAISE EXCEPTION 'cross-tenant project reference was accepted';
EXCEPTION
  WHEN foreign_key_violation THEN NULL;
END
$test$;

INSERT INTO secret_versions (
  org_id, project_id, environment_id, secret_id, version,
  value_ciphertext, nonce, auth_tag, encryption_key_version, author_user_id
) VALUES (
  '10000000-0000-0000-0000-000000000001',
  '40000000-0000-0000-0000-000000000004',
  '50000000-0000-0000-0000-000000000005',
  '60000000-0000-0000-0000-000000000006',
  1, '\x01', '\x000000000000000000000000', '\x00000000000000000000000000000000', 1,
  '30000000-0000-0000-0000-000000000003'
);

INSERT INTO tags (id, org_id, name, color) VALUES
  ('70000000-0000-0000-0000-000000000007', '10000000-0000-0000-0000-000000000001', 'database', '#336699');

INSERT INTO secret_tags (org_id, project_id, environment_id, secret_id, tag_id) VALUES
  ('10000000-0000-0000-0000-000000000001', '40000000-0000-0000-0000-000000000004', '50000000-0000-0000-0000-000000000005', '60000000-0000-0000-0000-000000000006', '70000000-0000-0000-0000-000000000007');

INSERT INTO api_keys (id, org_id, name, prefix, token_hash, access) VALUES
  ('80000000-0000-0000-0000-000000000008', '10000000-0000-0000-0000-000000000001', 'CI', 'himi_ci1234', '\x0102', 'read_only');

DO $test$
BEGIN
  INSERT INTO audit_events (org_id, actor_type, actor_api_key_id, action, resource_type) VALUES
    ('20000000-0000-0000-0000-000000000002', 'api_key', '80000000-0000-0000-0000-000000000008', 'cross.tenant', 'database');
  RAISE EXCEPTION 'cross-tenant API-key audit actor was accepted';
EXCEPTION
  WHEN foreign_key_violation THEN NULL;
END
$test$;

INSERT INTO audit_events (org_id, actor_type, action, resource_type, resource_id) VALUES
  ('10000000-0000-0000-0000-000000000001', 'system', 'schema.tested', 'database', 'core');

ROLLBACK;

SELECT 'core schema tests passed' AS result;
