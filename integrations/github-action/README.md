# Himitsu Secrets — GitHub Action

Loads secrets from a Himitsu environment into a workflow.

## Use

```yaml
- uses: sirsjg/himitsu/integrations/github-action@v1
  with:
    api-url: https://himitsu.example.com
    token: ${{ secrets.HIMITSU_TOKEN }}
    project: 11111111-1111-1111-1111-111111111111
    environment: 22222222-2222-2222-2222-222222222222

- run: ./deploy.sh   # DATABASE_URL, API_KEY, … are in the environment
```

Every value is registered with `::add-mask::` before anything else happens, so it
is redacted if it reaches the log.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `api-url` | — | **Required.** Base URL of the Himitsu API. |
| `token` | — | **Required.** API token. Store it as a repository or environment secret. |
| `project` | — | **Required.** Project UUID. |
| `environment` | — | **Required.** Environment UUID. |
| `export-to` | `env` | `env`, `file`, `outputs`, or `none`. |
| `format` | `dotenv` | With `export-to: file` — `dotenv`, `json`, or `shell`. |
| `file` | — | Destination path for `export-to: file`. Written mode 0600. |
| `prefix` | — | Prefix applied to every exported name, e.g. `HIMITSU_`. |
| `include` | — | Comma or newline separated allowlist of keys. |
| `exclude` | — | Comma or newline separated denylist of keys. |
| `mask` | `true` | Register values for log redaction. Leave enabled. |

## Outputs

| Output | Description |
| --- | --- |
| `secret-count` | Number of secrets exported. |
| `config-version` | Environment config version that was read. |
| `keys` | Comma separated key **names** — no values, safe to log. |
| `file` | Path written, with `export-to: file`. |

## Export modes

**`env`** (default) exports to subsequent steps via `GITHUB_ENV`. Keys that are
not valid POSIX environment variable names are skipped with a warning naming the
key (never its value). Multi-line values are handled with a random per-write
heredoc delimiter, so a value cannot inject additional variables.

**`file`** renders the whole environment to disk with mode 0600, set before the
content is written so plaintext is never briefly world-readable.

```yaml
- uses: sirsjg/himitsu/integrations/github-action@v1
  with:
    api-url: https://himitsu.example.com
    token: ${{ secrets.HIMITSU_TOKEN }}
    project: ${{ vars.HIMITSU_PROJECT }}
    environment: ${{ vars.HIMITSU_ENVIRONMENT }}
    export-to: file
    file: .env
    format: dotenv
```

> Delete the file before uploading artifacts or caching the workspace. The action
> warns about this but cannot enforce it.

**`outputs`** sets step outputs. These are persisted with the workflow run, so
prefer `env` unless a downstream job genuinely needs them.

**`none`** fetches and reports `secret-count` and `keys` without exporting —
useful for asserting an environment is populated before a deploy.

## Filtering

```yaml
with:
  include: DATABASE_URL,REDIS_URL   # allowlist
  exclude: DEBUG_TOKEN              # denylist; wins over include
  prefix: APP_                      # APP_DATABASE_URL, …
```

Excluded secrets are not masked, since masking them would needlessly redact
unrelated text in the log.

## Token scope

Use a `read_only`, environment-scoped key. The action never writes to Himitsu.

## Development

```sh
npm test        # 26 tests, no network
npm run build   # emits dist/, which must be committed
```

`dist/` is committed because GitHub runs a published action straight from its
build output; the repository `.gitignore` carries an explicit exception for it.
The action has no runtime dependencies — only Node built-ins and `fetch` — so
there is no vendored `node_modules` to audit.
