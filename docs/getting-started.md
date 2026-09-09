# Getting started

This walkthrough takes a new Himitsu organization from an empty workspace to a project that can supply configuration to CI and application processes. There is no hosted version of Himitsu, so complete the [self-hosting guide](self-hosting.md) — or the quick start in the [README](../README.md) — before starting here.

## 1. Create the organization

Sign up with a work email, verify it, sign in, and create or select an organization. The organization is the tenant boundary: memberships, projects, encryption keys, API keys, tags, and audit events never cross it.

Verification is required before the first sign-in. Set `RESEND_API_KEY` and `HIMITSU_EMAIL_FROM` to have the verification email actually sent; see [self-hosting](self-hosting.md). Without a key, delivery is discarded and no account can complete signup. On a local or single-operator install you can instead set `HIMITSU_EMAIL_DELIVERY=log` and read the verification link from the API log (`docker compose logs api`) — those links carry live tokens, so never do that where logs are shared.

The Projects page shows a first-run checklist when the organization has no projects. Organization owners and administrators can finish profile, member, tag, API-key, and retention setup from **Settings**.

## 2. Create the first project

Select **New project**, then provide a readable name and a stable lowercase slug. New projects receive development, staging, and protected production environments. Use a separate project when the configuration has a different ownership or deployment lifecycle.

Open the project and confirm that the environment tabs match the systems you intend to deploy. Select **Manage** at the end of the tab row to add, rename, reorder, protect, or delete environments; the order you set there drives the tabs and the cross-environment matrix. Add custom environments only when they represent a real deployment target.

## 3. Import an existing `.env`

In the development environment, select **Bulk paste**, choose **.env**, and paste or upload the file. Himitsu parses quotes, escapes, multiline values, comments, and `export` assignments. It shows adds, updates, and conflicts before any value is written.

Choose a conflict policy deliberately:

- **Skip** preserves every existing value.
- **Overwrite** replaces existing values with the import.
- **Merge select** writes only the checked keys.

Commit the preview, then use the cross-environment matrix to review missing keys. Promote selected keys to staging or production only after checking the target. Protected environments require an owner or administrator.

Do not commit the source `.env` file. Delete temporary copies securely after confirming the import.

## 4. Configure the CLI

Build the repository CLI and bind the current directory to the project and environment IDs shown by the API or browser requests:

```sh
npm run build --workspace @himitsu/cli
npm exec --workspace @himitsu/cli -- himitsu config set \
  --project PROJECT_UUID \
  --environment ENVIRONMENT_UUID \
  --api-url https://himitsu.example.com
```

For interactive use, authenticate with a session:

```sh
npm exec --workspace @himitsu/cli -- himitsu login --email you@example.com
npm exec --workspace @himitsu/cli -- himitsu check
```

The repository mapping is stored as an owner-only `.himitsu.json`. Session credentials are stored under `~/.config/himitsu/credentials.json` (or `HIMITSU_CONFIG_HOME`) with owner-only permissions. See the [CLI reference](cli.md) for every command.

## 5. Connect CI

In **Settings → API keys**, create a read-only project or project+environment key. Set an expiry, copy the token from its one-time reveal, store it in the CI provider's encrypted secret store as `HIMITSU_TOKEN`, and dismiss the reveal. Himitsu stores only its hash.

A CI job can fail on configuration drift and run a process with secrets injected only into its environment:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: 22
      cache: npm
  - run: npm ci
  - run: npm run build --workspace @himitsu/cli
  - run: npm exec --workspace @himitsu/cli -- himitsu config set --project "$HIMITSU_PROJECT_ID" --environment "$HIMITSU_ENVIRONMENT_ID" --api-url "$HIMITSU_API_URL"
  - run: npm exec --workspace @himitsu/cli -- himitsu check
    env:
      HIMITSU_TOKEN: ${{ secrets.HIMITSU_TOKEN }}
  - run: npm exec --workspace @himitsu/cli -- himitsu run -- npm test
    env:
      HIMITSU_TOKEN: ${{ secrets.HIMITSU_TOKEN }}
```

Provide `HIMITSU_TOKEN` to every Himitsu command that needs authentication. Store the project, environment, and API URL as non-secret CI variables. Prefer a distinct key per workload, the narrowest scope, read-only access, and a short expiry. Revoke it immediately when a job or repository is retired.

## 6. Connect an application runtime

Applications can use the CLI wrapper or fetch the optimized runtime endpoint once at boot:

```sh
curl --fail-with-body \
  --header "Authorization: Bearer $HIMITSU_TOKEN" \
  --header 'Accept: application/json' \
  "$HIMITSU_API_URL/api/v1/projects/$HIMITSU_PROJECT_ID/environments/$HIMITSU_ENVIRONMENT_ID/secrets/runtime"
```

Persist the returned ETag in memory and send it as `If-None-Match` on the next fetch. An unchanged configuration returns `304`; a changed response includes a monotonically increasing `configVersion`. Never log the response body, put it in build artifacts, or cache it on shared disk.

## Ready-state checklist

- The organization profile and audit retention policy are correct.
- Every person has the smallest suitable role.
- Development configuration was imported through a reviewed preview.
- The consistency report has no unexplained errors.
- Production writes require an elevated role.
- CI uses an expiring, read-only, narrowly scoped API key.
- Runtime fetches and exports appear in the audit log with the expected actor.

Continue with the [API reference](api-reference.md), [CLI reference](cli.md), or [self-hosting guide](self-hosting.md).
