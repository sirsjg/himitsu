#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?Set DATABASE_URL to a disposable PostgreSQL database}"

database_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f "$database_dir/migrations/0001_core.sql"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f "$database_dir/tests/core_schema.sql"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f "$database_dir/migrations/0001_core.down.sql"

remaining_relations="$(psql "$DATABASE_URL" -Atqc \
  "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'S')")"

if [[ "$remaining_relations" != "0" ]]; then
  echo "down migration left $remaining_relations tables or sequences" >&2
  exit 1
fi

echo "migration, constraints, indexes, and rollback validated"
