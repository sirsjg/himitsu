#!/usr/bin/env bash
set -euo pipefail

for workspace in audit crypto auth imports tenancy authz projects environments secrets api-keys consistency api cli web; do
  npm run build --workspace "@himitsu/$workspace"
done
