#!/usr/bin/env bash
set -euo pipefail

: "${TEST_DATABASE_URL:?Set TEST_DATABASE_URL to a fresh, disposable PostgreSQL database}"
: "${TEST_APP_DATABASE_URL:?Set TEST_APP_DATABASE_URL for the temporary himitsu_app role}"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

DATABASE_URL="$TEST_DATABASE_URL" ./packages/database/scripts/test-schema.sh

for workspace in audit crypto auth tenancy authz projects environments secrets api-keys consistency; do
  TEST_DATABASE_URL="$TEST_DATABASE_URL" TEST_APP_DATABASE_URL="$TEST_APP_DATABASE_URL" \
    npm run test:postgres --workspace "@himitsu/$workspace"
done

TEST_DATABASE_URL="$TEST_DATABASE_URL" TEST_APP_DATABASE_URL="$TEST_APP_DATABASE_URL" \
  npm run test:postgres --workspace @himitsu/api
