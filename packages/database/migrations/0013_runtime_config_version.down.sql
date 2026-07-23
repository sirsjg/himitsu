BEGIN;
DROP TRIGGER IF EXISTS secrets_bump_environment_config_version ON secrets;
DROP FUNCTION IF EXISTS bump_environment_config_version();
ALTER TABLE environments DROP COLUMN IF EXISTS config_version;
COMMIT;
