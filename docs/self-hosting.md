# Self-hosting Himitsu

The supported self-hosted deployment uses Docker Compose, PostgreSQL 16, a Node 22 API image, and an Nginx web image. The API emits JSON logs to stdout, exposes unauthenticated liveness and database-readiness probes, and exports a small Prometheus text endpoint without tenant or secret labels.

Prerequisites are Docker Engine with Compose v2, persistent storage sized for PostgreSQL plus backup generations, an HTTPS reverse proxy or load balancer for any non-local deployment, and two independent secure locations for the application master key and backup passphrase. The included Nginx container listens on HTTP port 8080; terminate TLS in front of it and forward the original scheme and client address. Secure session cookies will not work over public plain HTTP.

## First deployment

1. Copy `.env.example` to `.env` and replace both database passwords with different URL-safe random values.
2. Create `secrets/master-key` containing one canonical base64-encoded 32-byte key and `secrets/backup-passphrase` containing a long independent passphrase. Restrict both files to the deployment account: `chmod 600 secrets/master-key secrets/backup-passphrase`.
3. Start the stack with `docker compose up --build -d`.
4. Confirm `http://localhost:8080/health/live` returns `{"status":"ok"}` and `/health/ready` returns `{"status":"ready"}`.

The one-shot `migrate` service runs before the API. It holds a PostgreSQL advisory lock, applies each forward SQL migration once, validates the stored SHA-256 checksum on later starts, provisions the non-superuser `himitsu_app` role, and records versions in `schema_migrations`. A checksum mismatch fails deployment; shipped migrations must never be edited.

The application master key is not stored in PostgreSQL. Losing it makes wrapped organization keys unusable. Back it up separately from database backups, with access limited to operators. Rotate it only through an application-supported key-rotation procedure; replacing the file in place does not rewrap existing keys.

## Email

Signing in requires a verified email address, so a deployment that anyone else will use needs working delivery.

Set `RESEND_API_KEY` and `HIMITSU_EMAIL_FROM` and Himitsu sends real mail through [Resend](https://resend.com); verification, password reset, and organization invitations all work. The sending domain must be verified with Resend first, and `HIMITSU_EMAIL_FROM` must use that domain.

```sh
RESEND_API_KEY=re_...
HIMITSU_EMAIL_FROM="Himitsu <no-reply@example.com>"
HIMITSU_EMAIL_REPLY_TO=support@example.com   # optional
HIMITSU_APP_ORIGIN=https://himitsu.example.com
```

`HIMITSU_APP_ORIGIN` matters: it builds the links in the email, so getting it wrong sends people somewhere that cannot consume the token.

Without a key the behaviour is unchanged. `HIMITSU_EMAIL_DELIVERY` selects a mode explicitly and overrides the key when set:

| Mode | Behaviour |
| --- | --- |
| unset | `resend` when `RESEND_API_KEY` is present, otherwise `noop` |
| `noop` | Discards all delivery email. Safe, but **no account can complete signup**. |
| `log` | Prints action links to API stdout. The links carry live authentication tokens. |
| `resend` | Sends through Resend. Fails at startup if the key is missing. |

Use `log` only on a local or single-operator install whose logs are not shared or shipped to an aggregator.

A send failure is logged at error level and does not fail the request. That is deliberate: `requestPasswordReset` only reaches delivery for an address that has an account, so raising an error would tell an attacker which addresses are registered. Watch for `"msg":"email delivery failed"` in the API logs — with delivery misconfigured, signup appears to succeed and the email never arrives.

The API logs its resolved mode once at startup (`email delivery mode: …`) and warns explicitly when mail is being discarded.

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
