#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?Set DATABASE_URL to the PostgreSQL database to restore}"
: "${BACKUP_PASSPHRASE_FILE:?Set BACKUP_PASSPHRASE_FILE to the backup passphrase file}"
[[ "${RESTORE_CONFIRM:-}" == "restore-himitsu" ]] || { echo "Set RESTORE_CONFIRM=restore-himitsu to acknowledge the destructive restore" >&2; exit 2; }

backup="${1:?Usage: restore.sh /path/to/himitsu-TIMESTAMP.dump.enc}"
[[ -r "$backup" ]] || { echo "Encrypted backup is not readable: $backup" >&2; exit 1; }
[[ -r "$BACKUP_PASSPHRASE_FILE" ]] || { echo "Backup passphrase file is not readable" >&2; exit 1; }

openssl enc -d -aes-256-cbc -pbkdf2 -iter 250000 -pass "file:$BACKUP_PASSPHRASE_FILE" -in "$backup" \
  | pg_restore --dbname="$DATABASE_URL" --clean --if-exists --no-owner --no-acl --exit-on-error

echo "Himitsu restore completed"
