BEGIN;

ALTER TABLE environments ADD COLUMN purge_after timestamptz;
ALTER TABLE environments ADD CONSTRAINT environments_deletion_window_check CHECK (
  purge_after IS NULL OR (deleted_at IS NOT NULL AND purge_after > deleted_at)
);

ALTER TABLE secrets ADD COLUMN deleted_by_environment_at timestamptz;
ALTER TABLE secrets ADD CONSTRAINT secrets_environment_deletion_check
  CHECK (deleted_by_environment_at IS NULL OR deleted_at IS NOT NULL);

CREATE FUNCTION create_default_project_environments() RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  default_environments jsonb;
BEGIN
  default_environments := NEW.settings -> 'defaultEnvironments';
  IF default_environments IS NULL
    OR jsonb_typeof(default_environments) <> 'array'
    OR jsonb_array_length(default_environments) = 0
  THEN
    default_environments := '["development", "staging", "production"]'::jsonb;
  END IF;

  INSERT INTO environments (org_id, project_id, name, slug, display_order, protected)
  SELECT
    NEW.org_id,
    NEW.id,
    initcap(replace(value, '-', ' ')),
    value,
    ordinality - 1,
    value IN ('production', 'prod')
  FROM jsonb_array_elements_text(default_environments) WITH ORDINALITY;

  RETURN NEW;
END
$function$;

CREATE TRIGGER projects_create_default_environments
AFTER INSERT ON projects
FOR EACH ROW EXECUTE FUNCTION create_default_project_environments();

INSERT INTO environments (org_id, project_id, name, slug, display_order, protected)
SELECT
  p.org_id,
  p.id,
  initcap(replace(default_environment.value, '-', ' ')),
  default_environment.value,
  default_environment.ordinality - 1,
  default_environment.value IN ('production', 'prod')
FROM projects p
CROSS JOIN LATERAL jsonb_array_elements_text(
  CASE
    WHEN jsonb_typeof(p.settings -> 'defaultEnvironments') = 'array'
      AND jsonb_array_length(p.settings -> 'defaultEnvironments') > 0
    THEN p.settings -> 'defaultEnvironments'
    ELSE '["development", "staging", "production"]'::jsonb
  END
) WITH ORDINALITY AS default_environment(value, ordinality)
WHERE p.deleted_at IS NULL
  AND NOT EXISTS (
    SELECT 1 FROM environments e WHERE e.project_id = p.id
  )
ON CONFLICT (org_id, project_id, slug) DO NOTHING;

COMMIT;
