#!/usr/bin/env bash
set -euo pipefail

: "${MIGRATION_DATABASE_URL:?Set MIGRATION_DATABASE_URL to the PostgreSQL owner connection}"
: "${APP_DATABASE_PASSWORD:?Set APP_DATABASE_PASSWORD for the non-bypass application role}"

migration_dir="${MIGRATION_DIR:-/app/packages/database/migrations}"
[[ -d "$migration_dir" ]] || { echo "Migration directory not found: $migration_dir" >&2; exit 1; }

migrations=()
while IFS= read -r migration; do migrations+=("$migration"); done < <(find "$migration_dir" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]_*.sql' ! -name '*.down.sql' | sort)
[[ ${#migrations[@]} -gt 0 ]] || { echo "No forward migrations found in $migration_dir" >&2; exit 1; }

{
  printf '%s\n' '\set ON_ERROR_STOP on'
  printf '%s\n' "SELECT pg_advisory_lock(hashtext('himitsu-schema-migrations'));"
  printf '%s\n' "CREATE TABLE IF NOT EXISTS public.schema_migrations (version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());"
  printf '%s\n' "SELECT format('CREATE ROLE himitsu_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', :'app_password') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'himitsu_app') \gexec"
  printf '%s\n' "SELECT format('ALTER ROLE himitsu_app PASSWORD %L', :'app_password') \gexec"
  for migration in "${migrations[@]}"; do
    version="$(basename "$migration" .sql)"
    checksum="$(sha256sum "$migration" | awk '{print $1}')"
    printf "SELECT NOT EXISTS (SELECT 1 FROM public.schema_migrations WHERE version = '%s') AS migration_pending, COALESCE((SELECT checksum = '%s' FROM public.schema_migrations WHERE version = '%s'), true) AS migration_valid \\gset\n" "$version" "$checksum" "$version"
    printf '%s\n' '\if :migration_valid' '\else' "\echo Migration checksum mismatch: $version" 'SELECT 1 / 0;' '\endif'
    printf '%s\n' '\if :migration_pending'
    printf '\ir %s\n' "$migration"
    printf "INSERT INTO public.schema_migrations (version, checksum) VALUES ('%s', '%s');\n" "$version" "$checksum"
    printf '%s\n' '\endif'
  done
  printf '%s\n' 'GRANT CONNECT ON DATABASE :"DBNAME" TO himitsu_app;'
  printf '%s\n' "GRANT USAGE ON SCHEMA public TO himitsu_app;"
  printf '%s\n' "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO himitsu_app;"
  printf '%s\n' "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO himitsu_app;"
  printf '%s\n' "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO himitsu_app;"
  printf '%s\n' "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO himitsu_app;"
  printf '%s\n' "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO himitsu_app;"
  printf '%s\n' "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO himitsu_app;"
  printf '%s\n' "GRANT SELECT ON public.schema_migrations TO himitsu_app;"
  printf '%s\n' "SELECT pg_advisory_unlock(hashtext('himitsu-schema-migrations'));"
} | psql "$MIGRATION_DATABASE_URL" --quiet --set=app_password="$APP_DATABASE_PASSWORD"

echo "Himitsu database migrations are current"
