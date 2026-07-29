# Contributing to Himitsu

Thanks for looking at this. Himitsu is a secrets manager, so the bar for changes is higher than it would be for most projects: a mistake here leaks other people's credentials. That shapes most of what follows.

Before you start on anything substantial, please open an issue and describe what you want to do. A design conversation before the code is written is much cheaper for both of us than a rejected pull request.

**Security vulnerabilities do not go here.** Report them privately — see [SECURITY.md](SECURITY.md).

## Getting set up

You need Node.js 22 or newer. PostgreSQL 16 is needed for the integration suites, Go (stable) for the modules under `integrations/`, and Docker for the container packaging checks.

```sh
npm ci
npm run build
```

**Build before anything else.** Every workspace package resolves its siblings through `exports.types` pointing at `dist/src/index.d.ts`, so `typecheck`, `test`, and `docs:check` all fail with `Cannot find module '@himitsu/…'` on a clean checkout until `scripts/build-all.sh` has produced them. This trips up nearly everyone once.

## The checks

These are exactly what CI runs, in the same order. Run them locally before opening a pull request.

```sh
npm run build        # dependency-ordered build; must come first
npm run typecheck
npm test             # unit suites across all workspaces
npm run docs:check   # documentation structure, links, and OpenAPI freshness
```

The browser suite needs Playwright's Chromium:

```sh
npx playwright install --with-deps chromium
npm run test:e2e
```

The PostgreSQL matrix needs two connection strings pointing at a **fresh, disposable** database. It creates roles and applies migrations, so do not aim it at anything you care about:

```sh
export TEST_DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/himitsu_test
export TEST_APP_DATABASE_URL=postgresql://himitsu_app:himitsu_app_test@127.0.0.1:5432/himitsu_test
npm run test:postgres
```

The Go modules are built standalone with `GOWORK=off` so a broken module cannot be masked by the workspace:

```sh
cd integrations/client        # or operator, or terraform-provider
GOWORK=off gofmt -l .         # must print nothing
GOWORK=off go vet ./...
GOWORK=off go test -race ./...
```

Container packaging:

```sh
docker compose --env-file .env.example config --quiet
docker build --target api --tag himitsu-api:test .
```

## Things CI will fail you for

A few checks catch generated files that were not regenerated. They are easy to miss:

- **OpenAPI drift.** `docs/openapi.json` is generated. If you change a route, schema, or its metadata, run `npm run docs:openapi` and commit the result.
- **Stale GitHub Action build.** GitHub runs `integrations/github-action` straight from its committed `dist/`, so that one build output is tracked. Run `npm run build` in that directory and commit `dist/`.
- **Stale operator manifests.** If you touch the operator's API types, regenerate with `controller-gen` (see the `integrations-operator-manifests` job in `.github/workflows/ci.yml`) and commit the CRDs, RBAC, and deepcopy output.
- **Migrations that changed.** Shipped migrations are checksummed and must never be edited — a mismatch fails deployment for everyone who already ran them. Add a new forward migration instead.

## Code conventions

Match the surrounding code rather than importing a style from elsewhere. Specifically:

- TypeScript throughout, ES modules, no build step beyond `tsc` and Vite.
- Domain logic lives in `packages/*` and stays free of HTTP concerns. `apps/api` wires those services to Fastify routes. Keep that separation.
- Every authenticated route needs an explicit, fail-closed permission mapping. There is a test that asserts this; do not work around it.
- Parameterize every SQL value. Table identifiers come from internal allowlists, never from input.
- Comments explain *why*, not *what*. The existing comments are a good guide — most of them exist because something non-obvious would otherwise bite the next reader.

## Security-sensitive review rules

Changes touching these areas get scrutinized harder and may take longer to merge:

- `packages/crypto` — envelope encryption, key wrapping, rotation.
- `packages/auth` and `packages/authz` — sessions, password handling, permission resolution.
- `packages/tenancy` — the organization boundary and row-level-security enforcement.
- Any migration affecting RLS policies.

Rules for these paths:

- Never log, format, or include in an error message: plaintext secret values, ciphertext, key material, tokens, passwords, or session identifiers. Crypto errors are deliberately generic and must stay that way.
- Never put secret values or credential material into audit metadata. The allowlist validator will reject it, and that validator is not to be loosened.
- Do not add a dependency to these packages without raising it in the issue first. Supply-chain surface is a real cost here.
- New cryptographic primitives, modes, or key-handling flows need a design discussion before implementation. Do not roll your own.

## Pull requests

Keep them focused — one logical change per pull request. A large mechanical refactor mixed with a behavior change is very hard to review safely.

- Write a description that explains the motivation, not just the diff.
- Include tests. Bug fixes should include a test that fails before the fix.
- Update the relevant documentation in `docs/` in the same pull request. `npm run docs:check` enforces structure and links but cannot tell whether the prose became wrong.
- Note explicitly if the change affects a security property, a stored data format, or an existing deployment's upgrade path.

Contributions are accepted under the [Apache License 2.0](LICENSE), the same license as the project. There is no separate CLA.

## Project scope

Himitsu is deliberately narrow. Things likely to be accepted: correctness and security fixes, test coverage, documentation, better error messages, deployment and integration improvements, accessibility fixes.

Things likely to be declined without a strong case: alternative database backends, plugin systems, and features that widen the trust boundary. Every one of those multiplies the surface that has to stay correct, and this project does not yet have the review capacity to carry them.
