BEGIN;

DROP FUNCTION IF EXISTS resolve_api_key_identity(text);
DROP FUNCTION consume_api_key(text, bytea);

CREATE FUNCTION consume_api_key(
  candidate_prefix text,
  candidate_hash bytea
) RETURNS TABLE (
  id uuid,
  org_id uuid,
  project_id uuid,
  environment_id uuid,
  name text,
  prefix text,
  access api_key_access,
  expires_at timestamptz,
  last_used_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  UPDATE public.api_keys AS key
  SET last_used_at = GREATEST(COALESCE(key.last_used_at, statement_timestamp()), statement_timestamp())
  WHERE key.prefix = candidate_prefix
    AND key.token_hash = candidate_hash
    AND octet_length(candidate_hash) = 32
    AND key.revoked_at IS NULL
    AND (key.expires_at IS NULL OR key.expires_at > statement_timestamp())
    AND EXISTS (
      SELECT 1 FROM public.organizations organization
      WHERE organization.id = key.org_id AND organization.deleted_at IS NULL
    )
    AND (
      key.project_id IS NULL
      OR EXISTS (
        SELECT 1 FROM public.projects project
        WHERE project.org_id = key.org_id
          AND project.id = key.project_id
          AND project.deleted_at IS NULL
      )
    )
    AND (
      key.environment_id IS NULL
      OR EXISTS (
        SELECT 1 FROM public.environments environment
        WHERE environment.org_id = key.org_id
          AND environment.project_id = key.project_id
          AND environment.id = key.environment_id
          AND environment.deleted_at IS NULL
      )
    )
  RETURNING key.id, key.org_id, key.project_id, key.environment_id, key.name,
            key.prefix, key.access, key.expires_at, key.last_used_at
$function$;

COMMIT;
