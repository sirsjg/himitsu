# CLI reference

The `himitsu` CLI uses the REST API for repository configuration, imports, audited exports, consistency checks, and secret operations. It never stores values when `run` is used and writes export files with mode `0600`.

## Build and invoke

From this repository:

```sh
npm run build --workspace @himitsu/cli
npm exec --workspace @himitsu/cli -- himitsu help
```

The examples below use `himitsu` for readability. Replace it with `npm exec --workspace @himitsu/cli -- himitsu` when running the workspace build directly.

## Repository configuration

```sh
himitsu config set \
  --project PROJECT_UUID \
  --environment ENVIRONMENT_UUID \
  --api-url https://himitsu.example.com
```

This writes `.himitsu.json` in the current directory with owner-only permissions. Commands search the current directory and its parents for that file, so one mapping can cover an entire repository. The file contains identifiers and the API URL, not credentials or secret values; it is safe to version only when those identifiers are not considered sensitive by your organization.

## Authentication

Interactive session:

```sh
himitsu login --email you@example.com
himitsu login --email you@example.com --org ORGANIZATION_UUID
printf '%s\n' "$HIMITSU_PASSWORD" | himitsu login --email you@example.com --password-stdin
```

Session credentials are written to `~/.config/himitsu/credentials.json`, or `$HIMITSU_CONFIG_HOME/credentials.json`, with directory mode `0700` and file mode `0600`. Use `--org` when the account belongs to multiple organizations.

Automation should set an API key for only the process that needs it:

```sh
HIMITSU_TOKEN="${HIMITSU_TOKEN:?missing}" himitsu check
```

Do not place tokens on a command line, in `.himitsu.json`, or in shell history. Use the CI provider's encrypted secret store.

## Pull and export

Write a deterministic dotenv file:

```sh
himitsu pull --format dotenv --out .env.local
```

Pipe flat or nested JSON:

```sh
himitsu pull --format json
himitsu pull --format json --nested --delimiter __ | jq .DATABASE.HOST
```

Generate shell assignments:

```sh
himitsu pull --format shell > /tmp/himitsu-env.sh
```

Supported formats are `dotenv`, `json`, and `shell`. Output defaults to stdout (`--out -`). Files are created or corrected to mode `0600`. Every export is authorized as a secret read and audit-logged with its actor, format, nesting mode, and secret count. Treat stdout, shell traces, and redirected files as plaintext-secret surfaces.

## Push and import

```sh
himitsu push .env --format dotenv --strategy skip
himitsu push config.json --format json --strategy overwrite --delimiter __
```

The extension selects JSON automatically for `.json`; otherwise dotenv is the default. Strategies:

- `skip`: create missing keys and preserve existing keys.
- `overwrite`: create missing keys and replace existing keys.
- `merge`: send the import through the merge-select contract.

The browser provides the richer preview and per-key selection workflow. Use it for unfamiliar or production-bound imports.

## Run a process without a file

```sh
himitsu run -- npm test
himitsu run -- node server.js
```

`run` fetches the mapped environment's values, merges them into the child environment, and starts the command after `--`. It does not write a dotenv or JSON file. Child processes, crash reporters, and debug tooling can still expose environment variables; configure them accordingly.

## Consistency check

```sh
himitsu check
```

The command prints a value-free summary and exits `0` when healthy or `1` when active drift exists. Findings cover missing keys, empty or placeholder values, naming violations, and case-only duplicates. Use the exit status as a CI quality gate.

## Individual secret operations

```sh
himitsu secrets get DATABASE_URL
himitsu secrets set DATABASE_URL
printf '%s\n' "$NEW_DATABASE_URL" | himitsu secrets set DATABASE_URL --value-stdin
himitsu secrets rm DATABASE_URL
```

`get` prints plaintext to stdout. `set` prompts without echo unless `--value-stdin` is used. Updating an existing secret uses its current version as an optimistic concurrency precondition. `rm` performs the server's audited soft-delete workflow.

## Exit codes

- `0`: command succeeded; for `check`, the project is healthy.
- `1`: request or runtime failure; for `check`, active drift exists.
- `2`: invalid command, option, local configuration, or missing key.
- `3`: missing, expired, or forbidden authentication.

API errors are printed to stderr without response internals. Reauthenticate after exit code `3`, and verify the configured project/environment scope before expanding a key's privileges.
