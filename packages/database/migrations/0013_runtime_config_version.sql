BEGIN;

ALTER TABLE environments
  ADD COLUMN config_version bigint NOT NULL DEFAULT 0 CHECK (config_version >= 0);

CREATE FUNCTION bump_environment_config_version() RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.current_version = 0 OR NEW.deleted_at IS NOT NULL THEN
      RETURN NEW;
    END IF;
  ELSIF NEW.current_version IS NOT DISTINCT FROM OLD.current_version
    AND NEW.deleted_at IS NOT DISTINCT FROM OLD.deleted_at
  THEN
    RETURN NEW;
  END IF;

  UPDATE environments
  SET config_version = config_version + 1
  WHERE org_id = NEW.org_id
    AND project_id = NEW.project_id
    AND id = NEW.environment_id;
  RETURN NEW;
END
$function$;

CREATE TRIGGER secrets_bump_environment_config_version
AFTER INSERT OR UPDATE OF current_version, deleted_at ON secrets
FOR EACH ROW EXECUTE FUNCTION bump_environment_config_version();

COMMIT;
