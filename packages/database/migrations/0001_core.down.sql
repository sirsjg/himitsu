BEGIN;

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS secret_tags;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS secret_versions;
DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS environments;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;

DROP TYPE IF EXISTS audit_actor_type;
DROP TYPE IF EXISTS api_key_access;
DROP TYPE IF EXISTS membership_status;
DROP TYPE IF EXISTS organization_role;

COMMIT;
