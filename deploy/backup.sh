#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${DATABASE_URL:?Set DATABASE_URL to the PostgreSQL database to back up}"
: "${BACKUP_PASSPHRASE_FILE:?Set BACKUP_PASSPHRASE_FILE to a protected passphrase file}"
[[ -r "$BACKUP_PASSPHRASE_FILE" ]] || { echo "Backup passphrase file is not readable" >&2; exit 1; }

backup_dir="${BACKUP_DIR:-/backups}"
mkdir -p "$backup_dir"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
destination="$backup_dir/himitsu-$timestamp.dump.enc"
temporary="$(mktemp "$backup_dir/.himitsu-backup.XXXXXX")"
trap 'rm -f "$temporary"' EXIT

pg_dump --format=custom --no-owner --no-acl "$DATABASE_URL" \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 250000 -salt -pass "file:$BACKUP_PASSPHRASE_FILE" -out "$temporary"
mv "$temporary" "$destination"
trap - EXIT
echo "$destination"
