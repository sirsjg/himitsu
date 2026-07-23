# Himitsu

Himitsu is a tenant-isolated secrets manager with encrypted versioned values, environment consistency checks, audit trails, a browser workspace, and a CLI.

## Development

The repository requires Node.js 22 and PostgreSQL 16 for integration tests.

```sh
npm ci
npm run typecheck
npm test
npm run build
```

Run the browser suite with `npm run test:e2e`. Run the complete schema and PostgreSQL integration matrix by setting `TEST_DATABASE_URL` and `TEST_APP_DATABASE_URL`, then executing `npm run test:postgres`.

## Deployment

Production Docker targets, automated migrations, health checks, metrics, encrypted backups, and release automation are included. See [the self-hosting and restore guide](docs/self-hosting.md) before deploying.
