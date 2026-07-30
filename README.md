# Himitsu

Himitsu is a self-hosted secrets manager. It stores configuration as encrypted, versioned values scoped to an organization, a project, and an environment, and it gives you a browser workspace, a CLI, a REST API, and integrations for Kubernetes, GitHub Actions, and Terraform to get those values where they need to go.

The part that is less common: Himitsu also tells you when your environments have **drifted** — a key present in staging but missing in production, a value that is still a placeholder, a name that violates your convention, two keys differing only by case. That check runs in CI and fails the build.

[![CI](https://github.com/sirsjg/himitsu/actions/workflows/ci.yml/badge.svg)](https://github.com/sirsjg/himitsu/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Status: early, unaudited, no production track record

Please read this before you put real credentials in it.

Himitsu is new. The cryptographic design has not been independently audited, there is no production deployment history, and the project has a single maintainer. The [security review](docs/security/review-2026-07-22.md) in this repository was written by the author, not by a third party.

The engineering is deliberate — per-organization data-encryption keys under a separately held master key, PostgreSQL row-level security enforcing the tenant boundary, fail-closed permission mapping on every authenticated route, append-only audit events, and a test suite that covers all of it. None of that is a substitute for external review, and none of it has been tested by an adversary who wanted in.

Run it for personal projects, run it for internal tooling, read the code, break it and tell me how. If you are choosing where your company's production credentials live, choose something with an audit and a track record — [OpenBao](https://openbao.org/), [Infisical](https://infisical.com/), or your cloud provider's secrets manager — and revisit this later.

There is no hosted version of Himitsu and none is planned. Self-hosting is the only way to run it.

## What it does

**Secrets and structure.** Organizations contain projects; projects contain environments (development, staging, and a protected production by default). Every secret value is versioned, and history is retained so you can see what changed and roll back.

**Encryption.** Values are encrypted with AES-256-GCM under a per-organization data-encryption key. That key is itself wrapped by a master key held outside the database, so a stolen database or backup yields ciphertext and wrapped keys only. Authenticated data binds each value to its organization, project, environment, secret ID, and record version, so ciphertext cannot be moved between tenants. See the [threat model](docs/security/threat-model.md) for what this does and does not protect.

**Tenant isolation.** Enforced in the application *and* in PostgreSQL through forced row-level security, so a missing check in application code does not silently become a cross-tenant read.

**Environment consistency.** Compare environments and get findings for missing keys, empty values, placeholder values, naming violations, and case-duplicate keys. Findings can be acknowledged or ignored with a reason. `himitsu check` exits non-zero in CI.

**Import.** Paste or upload a `.env` file. Quotes, escapes, multiline values, comments, and `export` assignments all parse. You see adds, updates, and conflicts as a preview before anything is written, with skip / overwrite / merge-select conflict policies.

**Audit.** Append-only events for sensitive reads and writes, API key use, and attributable authentication failures. Metadata goes through an allowlist validator that rejects credential and secret fields.

**Access control.** Role-based, with organization owners and administrators, project-level overrides, and protected environments requiring an elevated role. API keys are scoped to an organization, project, or project+environment, are read-only or read-write, carry an expiry, and are revealed exactly once — only a hash is stored.

**Getting values out.** A CLI (`pull`, `push`, `run`, `check`), a REST API with an ETag-based runtime endpoint that transfers nothing when configuration is unchanged, a [Kubernetes operator](integrations/operator), a [GitHub Action](integrations/github-action), a [Terraform provider](integrations/terraform-provider), and a [Go SDK](integrations/client).

## Quick start

You need Docker Engine with Compose v2. This brings up PostgreSQL, runs migrations, and serves the app on `http://localhost:8080`.

```sh
git clone https://github.com/sirsjg/himitsu.git
cd himitsu

# Configuration and two independent passwords.
cp .env.example .env
$EDITOR .env

# The master key: exactly 32 bytes, base64. Losing this makes every stored
# secret permanently unrecoverable — there is no reset path.
mkdir -p secrets
openssl rand -base64 32 > secrets/master-key
openssl rand -base64 48 > secrets/backup-passphrase
chmod 600 secrets/master-key secrets/backup-passphrase

docker compose up --build -d
```

Confirm it is healthy:

```sh
curl http://localhost:8080/health/ready   # {"status":"ready"}
```

### Completing signup

Signing in requires a verified email address, and **without a mail provider configured that email is discarded**, so a fresh install cannot complete signup without one extra step.

For a real deployment, add a [Resend](https://resend.com) key. Verification, password reset, and invitations then work:

```sh
# In .env — the domain must be verified with Resend, and the From address must use it.
RESEND_API_KEY=re_...
HIMITSU_EMAIL_FROM="Himitsu <no-reply@example.com>"
HIMITSU_APP_ORIGIN=https://himitsu.example.com
```

For a local or single-operator install, skip the provider and print the verification link to the API log instead:

```sh
# In .env — LOCAL OR SINGLE-OPERATOR USE ONLY. These links carry live tokens,
# so never enable this where logs are shared or shipped to a log aggregator.
HIMITSU_EMAIL_DELIVERY=log
```

Then sign up at `http://localhost:8080`, and take the link from the API logs:

```sh
docker compose logs api | grep verification
```

The API logs its delivery mode at startup, and warns when mail is being discarded. See [self-hosting](docs/self-hosting.md#email) for every mode and for why a send failure is logged rather than raised.

From here, follow the [getting started guide](docs/getting-started.md) to create an organization and project, import a `.env`, and connect CI.

### Before you expose it to a network

The quick start above is not a production deployment. At minimum you must terminate TLS in front of the app — session cookies use the `__Host-` prefix and the `Secure` flag and will not work over plain HTTP — and store the master key somewhere other than next to your database backups. Read [the self-hosting guide](docs/self-hosting.md) first; it covers deployment, master-key custody, health and metrics, encrypted backups, and the restore runbook.

## Documentation

- [Getting started](docs/getting-started.md) — organization and project setup, `.env` import, connecting CI and application runtimes.
- [Self-hosting](docs/self-hosting.md) — deployment, master-key custody, health, encrypted backups, restore, releases.
- [CLI reference](docs/cli.md) — repository mapping, authentication, `pull`/`push`/`run`/`check`, secret commands, exit codes.
- [REST API v1](docs/api-reference.md) — authentication, envelopes, resource index, and the generated [OpenAPI 3.1 contract](docs/openapi.json).
- [Integrations](integrations/README.md) — Kubernetes operator, GitHub Action, Terraform provider, Go SDK.
- [Architecture decision record](docs/adr/0001-system-architecture.md) — why the system is shaped this way.
- [Threat model](docs/security/threat-model.md) and [security review](docs/security/review-2026-07-22.md).

## How it is built

TypeScript throughout, ES modules, Node.js 22, PostgreSQL 16. Fastify for the API, React and Vite for the browser workspace, Go for the Kubernetes operator and Terraform provider.

```
apps/api           Fastify HTTP layer — routes, schemas, permission mapping
apps/web           React browser workspace
apps/cli           himitsu CLI
packages/          Domain logic, HTTP-free and independently tested:
  crypto             envelope encryption, key wrapping, DEK rotation
  auth  authz        sessions, passwords, permission resolution
  tenancy            the organization boundary and RLS enforcement
  secrets            versioned values
  consistency        environment drift findings
  projects  environments  api-keys  audit  imports  database
integrations/      Go SDK, Kubernetes operator, Terraform provider, GitHub Action
deploy/            migrate, backup, restore, nginx
docs/              the documentation above
```

Domain logic stays out of the HTTP layer, so the security-critical code can be tested directly against PostgreSQL without going through a route.

## Development

Node.js 22+, PostgreSQL 16 for the integration suites, Go (stable) for `integrations/`.

```sh
npm ci
npm run build      # must come first — packages resolve siblings through dist/
npm run typecheck
npm test
npm run docs:check
```

Browser suite:

```sh
npx playwright install --with-deps chromium
npm run test:e2e
```

PostgreSQL matrix, against a **fresh, disposable** database:

```sh
export TEST_DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/himitsu_test
export TEST_APP_DATABASE_URL=postgresql://himitsu_app:himitsu_app_test@127.0.0.1:5432/himitsu_test
npm run test:postgres
```

`npm run build` must run before `typecheck`, `test`, or `docs:check` on a clean checkout — every workspace package resolves its siblings through generated type declarations. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full set of checks, the generated files CI will fail you for forgetting, and the review rules for security-sensitive paths.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Open an issue before starting anything substantial.

Found a security vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md).

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[Apache License 2.0](LICENSE).

*Himitsu (秘密) is Japanese for "secret".*
