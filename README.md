# Himitsu

Himitsu is a tenant-isolated secrets manager with encrypted versioned values, environment consistency checks, audit trails, a browser workspace, and a CLI.

## Documentation

- [Getting started](docs/getting-started.md): create an organization and project, import `.env`, and connect CI/runtime consumers.
- [REST API v1](docs/api-reference.md): authentication, envelopes, resource index, and the generated [OpenAPI 3.1 contract](docs/openapi.json).
- [CLI reference](docs/cli.md): repository mapping, authentication, pull/push/run/check, secret commands, and exit codes.
- [Self-hosting](docs/self-hosting.md): deployment, master-key custody, health, encrypted backups, restore, and releases.
- [Architecture decision](docs/adr/0001-system-architecture.md) and [security threat model](docs/security/threat-model.md).

## Development

The repository requires Node.js 22 and PostgreSQL 16 for integration tests.

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run docs:check
```

Run the browser suite with `npm run test:e2e`. Run the complete schema and PostgreSQL integration matrix by setting `TEST_DATABASE_URL` and `TEST_APP_DATABASE_URL`, then executing `npm run test:postgres`.

## Deployment

Production Docker targets, automated migrations, health checks, metrics, encrypted backups, and release automation are included. See [the self-hosting and restore guide](docs/self-hosting.md) before deploying.
