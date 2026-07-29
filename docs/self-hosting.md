# Self-hosting Himitsu

The supported self-hosted deployment uses Docker Compose, PostgreSQL 16, a Node 22 API image, and an Nginx web image. The API emits JSON logs to stdout, exposes unauthenticated liveness and database-readiness probes, and exports a small Prometheus text endpoint without tenant or secret labels.

Prerequisites are Docker Engine with Compose v2, persistent storage sized for PostgreSQL plus backup generations, an HTTPS reverse proxy or load balancer for any non-local deployment, and two independent secure locations for the application master key and backup passphrase. The included Nginx container listens on HTTP port 8080; terminate TLS in front of it and forward the original scheme and client address. Secure session cookies will not work over public plain HTTP.

## First deployment

1. Copy `.env.example` to `.env` and replace both database passwords with different URL-safe random values.
2. Create `secrets/master-key` containing one canonical base64-encoded 32-byte key and `secrets/backup-passphrase` containing a long independent passphrase. Restrict both files to the deployment account: `chmod 600 secrets/master-key secrets/backup-passphrase`.
3. Start the stack with `docker compose up --build -d`.
4. Confirm `http://localhost:8080/health/live` returns `{"status":"ok"}` and `/health/ready` returns `{"status":"ready"}`.

Signing in requires a verified email address, and Himitsu currently ships only two delivery modes. `HIMITSU_EMAIL_DELIVERY=noop`, the default, silently discards verification, password-reset, and organization-invitation email — safe, but no account can complete signup. `HIMITSU_EMAIL_DELIVERY=log` prints the action links to API stdout; the links carry live authentication tokens, so use it only on a local or single-operator install whose logs are not shared or shipped to an aggregator.

There is no SMTP or transactional-email adapter yet. A deployment serving more than one person needs one implemented against the delivery interface in `apps/api/src/server.ts`, which takes the `sendEmailVerification`, `sendPasswordReset`, and `sendOrganizationInvitation` callbacks. Until that exists, treat external signup as unsupported and never log delivery tokens anywhere they can be read by someone who should not hold them.

The one-shot `migrate` service runs before the API. It holds a PostgreSQL advisory lock, applies each forward SQL migration once, validates the stored SHA-256 checksum on later starts, provisions the non-superuser `himitsu_app` role, and records versions in `schema_migrations`. A checksum mismatch fails deployment; shipped migrations must never be edited.

The application master key is not stored in PostgreSQL. Losing it makes wrapped organization keys unusable. Back it up separately from database backups, with access limited to operators. Rotate it only through an application-supported key-rotation procedure; replacing the file in place does not rewrap existing keys.

## Health, logs, and metrics

- `GET /health/live` proves the API event loop is serving requests.
- `GET /health/ready` runs `SELECT 1` against PostgreSQL and returns HTTP 503 when unavailable.
- `GET /metrics` returns Prometheus counters for responses, 5xx responses, and process uptime. It contains no tenant, user, project, secret, or path labels.
- API logs are newline-delimited JSON from Fastify/Pino. Collect container stdout and alert on repeated 5xx responses, readiness failures, restarts, and database saturation.

## Encrypted backup procedure

Run an on-demand encrypted backup with:

```sh
docker compose --profile ops run --rm backup
```

The command writes an owner-only `backups/himitsu-<UTC timestamp>.dump.enc`. PostgreSQL's custom dump stream is encrypted with AES-256-CBC using PBKDF2 (250,000 iterations); the passphrase comes from the mounted file and is never passed on the command line. Copy encrypted backups to a separate failure domain, retain several generations, and test restores regularly. A practical baseline is daily backups retained for 30 days plus monthly backups retained for one year.

Verify the newest file is non-empty, record its checksum, and confirm it cannot be listed by `pg_restore` before decryption. Database encryption does not replace protection of the independent Himitsu master key.

## Restore runbook

Restores replace objects in the destination database. Schedule downtime, stop the API, take a safety backup, and restore first into a disposable database whenever possible.

```sh
docker compose stop api web
docker compose run --rm \
  --entrypoint /usr/local/bin/restore.sh \
  -e RESTORE_CONFIRM=restore-himitsu \
  -e DATABASE_URL=postgresql://postgres:ADMIN_PASSWORD@db:5432/himitsu \
  backup /backups/himitsu-YYYYMMDDTHHMMSSZ.dump.enc
docker compose run --rm migrate
docker compose up -d api web
curl --fail http://localhost:8080/health/ready
```

After restoration, verify `schema_migrations`, authenticate with a non-production test account, inspect a project and its audit history, and confirm a secret can be decrypted. If the backup predates the current schema, the migration job advances it before the API starts.

## Releases

Pull requests build all three Docker targets in CI. Tags matching `vMAJOR.MINOR.PATCH` trigger `.github/workflows/release.yml`, which publishes multi-architecture API, web, and operations images to GitHub Container Registry with provenance and SBOM attestations. Pin immutable version tags or digests in production rather than tracking `latest`.

No version has been tagged yet, so no published images exist. Until the first release, `docker compose up --build` builds from source, and upgrading means pulling `main` and rebuilding. Treat `main` as unstable and take a verified backup before every upgrade.

Before an upgrade, read the release notes, take and verify an encrypted backup, preserve the exact master-key file, and pull immutable image tags. Start the migration service before replacing the API, verify readiness and `schema_migrations`, then exercise login, one secret read, runtime ETag behavior, and the audit viewer. Roll back application images only when their schema compatibility is documented; restore the database backup when a migration is not backward compatible.
