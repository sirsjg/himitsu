BEGIN;
DROP TRIGGER IF EXISTS projects_create_default_environments ON projects;
DROP FUNCTION IF EXISTS create_default_project_environments();
ALTER TABLE secrets DROP CONSTRAINT IF EXISTS secrets_environment_deletion_check;
ALTER TABLE secrets DROP COLUMN IF EXISTS deleted_by_environment_at;
ALTER TABLE environments DROP CONSTRAINT IF EXISTS environments_deletion_window_check;
ALTER TABLE environments DROP COLUMN IF EXISTS purge_after;
COMMIT;
