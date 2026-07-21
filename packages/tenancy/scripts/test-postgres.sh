#!/usr/bin/env bash
set -euo pipefail

: "${TEST_DATABASE_URL:?Set TEST_DATABASE_URL to a fresh, disposable PostgreSQL database}"
: "${TEST_APP_DATABASE_URL:?Set TEST_APP_DATABASE_URL to the app-role URL for that database}"

tenancy_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd "$tenancy_dir/../.." && pwd)"
database_dir="$repo_dir/packages/database"

cleanup() {
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "DROP OWNED BY himitsu_app; DROP ROLE IF EXISTS himitsu_app"
  for migration in 0005_tenancy.down.sql 0004_auth.down.sql 0003_audit_append_only.down.sql 0002_org_encryption_keys.down.sql 0001_core.down.sql; do
    psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/$migration"
  done
}
trap cleanup EXIT

for migration in 0001_core.sql 0002_org_encryption_keys.sql 0003_audit_append_only.sql 0004_auth.sql 0005_tenancy.sql; do
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/$migration"
done

psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE himitsu_app LOGIN PASSWORD 'himitsu_app_test' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO himitsu_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO himitsu_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO himitsu_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO himitsu_app;
SQL

TEST_DATABASE_URL="$TEST_DATABASE_URL" TEST_APP_DATABASE_URL="$TEST_APP_DATABASE_URL" \
  npm run test:integration --workspace @himitsu/tenancy

trap - EXIT
cleanup

remaining_relations="$(psql "$TEST_DATABASE_URL" -Atqc \
  "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'S')")"
[[ "$remaining_relations" = "0" ]]
echo "organization lifecycle, invitations, org switching, RLS isolation, and rollback validated"
