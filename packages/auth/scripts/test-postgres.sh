#!/usr/bin/env bash
set -euo pipefail
: "${TEST_DATABASE_URL:?Set TEST_DATABASE_URL to a fresh, disposable PostgreSQL database}"

auth_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd "$auth_dir/../.." && pwd)"
database_dir="$repo_dir/packages/database"

cleanup() {
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0005_tenancy.down.sql"
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0004_auth.down.sql"
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0003_audit_append_only.down.sql"
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0002_org_encryption_keys.down.sql"
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0001_core.down.sql"
}
trap cleanup EXIT

for migration in 0001_core.sql 0002_org_encryption_keys.sql 0003_audit_append_only.sql 0004_auth.sql 0005_tenancy.sql; do
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/$migration"
done
TEST_DATABASE_URL="$TEST_DATABASE_URL" npm run test:integration --workspace @himitsu/auth

trap - EXIT
cleanup
remaining_relations="$(psql "$TEST_DATABASE_URL" -Atqc \
  "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'S')")"
[[ "$remaining_relations" = "0" ]]
echo "account, token, session, CSRF, login throttling, active organization, and rollback validated"
