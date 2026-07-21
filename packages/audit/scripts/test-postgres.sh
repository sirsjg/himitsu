#!/usr/bin/env bash
set -euo pipefail

: "${TEST_DATABASE_URL:?Set TEST_DATABASE_URL to a fresh, disposable PostgreSQL database}"

audit_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd "$audit_dir/../.." && pwd)"
database_dir="$repo_dir/packages/database"

cleanup() {
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0003_audit_append_only.down.sql"
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0002_org_encryption_keys.down.sql"
  psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0001_core.down.sql"
}

trap cleanup EXIT
psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0001_core.sql"
psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0002_org_encryption_keys.sql"
psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f "$database_dir/migrations/0003_audit_append_only.sql"

TEST_DATABASE_URL="$TEST_DATABASE_URL" npm run test:integration --workspace @himitsu/audit

trap - EXIT
cleanup

remaining_relations="$(psql "$TEST_DATABASE_URL" -Atqc \
  "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'S')")"
if [[ "$remaining_relations" != "0" ]]; then
  echo "audit migration rollback left $remaining_relations tables or sequences" >&2
  exit 1
fi

echo "transactional audit capture, immutability, and rollback validated"
