# Terraform provider for Himitsu

Manages Himitsu projects, environments, secrets, tags, and API keys.

## Use

```hcl
terraform {
  required_providers {
    himitsu = {
      source  = "himitsu-io/himitsu"
      version = "~> 0.1"
    }
  }
}

provider "himitsu" {}   # reads HIMITSU_API_URL and HIMITSU_TOKEN
```

| Setting | Attribute | Environment variable |
| --- | --- | --- |
| API base URL | `api_url` | `HIMITSU_API_URL` |
| API token | `token` | `HIMITSU_TOKEN` |

Prefer the environment variables. A token written into configuration ends up in
version control.

See [`examples/main.tf`](examples/main.tf) for a full worked configuration.

## Secrets and Terraform state

> **Values managed by this provider are stored in Terraform state in plaintext.**

This is inherent to Terraform, not specific to Himitsu: any provider that manages
a secret puts it in state. It has two consequences worth deciding about
deliberately.

**Use an encrypted state backend with restricted access.** Local state files and
unencrypted buckets defeat the point of storing secrets in Himitsu at all.

**Consider not managing values in Terraform.** Declaring `himitsu_project`,
`himitsu_environment`, and `himitsu_api_key` in Terraform while letting people
set values through the CLI or UI gives you infrastructure-as-code for the
*structure* without copying every secret into state. The `himitsu_secrets` data
source still reads values when a downstream resource needs one.

Note also that refreshing a `himitsu_secret` calls the value-returning endpoint,
which records a `secret.read` audit event each time.

## Resources

### `himitsu_project`

| Attribute | | |
| --- | --- | --- |
| `name`, `slug` | required | |
| `description` | optional | |
| `default_environments` | optional | Environments created *with* the project. **Not tracked by this resource** — declare `himitsu_environment` resources if you want Terraform to manage them. |
| `tag_ids` | optional | |
| `id`, `org_id` | computed | |

Import: `terraform import himitsu_project.x <project_id>`

### `himitsu_environment`

| Attribute | | |
| --- | --- | --- |
| `project_id` | required | Forces replacement. |
| `name`, `slug` | required | |
| `protected` | optional, default `false` | Restricts writes to owners and admins. |
| `confirm_secrets_on_destroy` | optional, default `false` | Allow destroying an environment that still holds secrets. |
| `id`, `org_id`, `display_order` | computed | |

Destroying a populated environment fails unless `confirm_secrets_on_destroy` is
`true`. That is deliberate — losing an environment's secrets should take an
explicit configuration change.

Import: `terraform import himitsu_environment.x <project_id>/<environment_id>`

### `himitsu_secret`

| Attribute | | |
| --- | --- | --- |
| `project_id`, `environment_id`, `key` | required | All force replacement. |
| `value` | required, sensitive | |
| `notes`, `change_note` | optional | `change_note` is recorded on the version and shown in the audit log. |
| `allow_non_conforming_key` | optional, default `false` | |
| `tag_ids` | optional | |
| `id`, `current_version` | computed | |

Updates send `If-Match` with the last observed version. If someone changed the
secret since Terraform last read it, the apply fails with a clear message instead
of silently overwriting their change.

Import: `terraform import himitsu_secret.x <project_id>/<environment_id>/<KEY>`

### `himitsu_api_key`

| Attribute | | |
| --- | --- | --- |
| `name`, `access` | required | `access` is `read_only` or `read_write`. |
| `project_id`, `environment_id` | optional | Narrow the scope. `environment_id` requires `project_id`. |
| `expires_at` | optional | RFC 3339. |
| `token` | computed, sensitive | Returned only at creation. |
| `id`, `prefix`, `created_at` | computed | |

Every attribute forces replacement — the API mints a token once and has no update
operation. Destroying the resource revokes the key. A revoked key is treated as
absent on refresh, so the next apply mints a replacement.

> A token's effective permissions follow the Himitsu membership of the user whose
> credentials created it. If that person is removed or demoted, tokens they
> minted change with them.

### `himitsu_tag`

`name` and `color` (six-digit hex, validated at plan time). Import by id.

## Data sources

### `himitsu_project` / `himitsu_environment`

Look up by `id` or `slug`. `himitsu_environment` also requires `project_id`.

### `himitsu_secrets`

Reads a whole environment.

| Attribute | | |
| --- | --- | --- |
| `project_id`, `environment_id` | required | |
| `secrets` | computed, **sensitive** | Key → plaintext value. |
| `keys` | computed | Key names only. Not sensitive — usable in plan output. |
| `config_version` | computed | Increments on every secret change. |

## Development

```sh
go test ./...
go build -o terraform-provider-himitsu .
```

To try it against a local build, point Terraform at the binary with a
[dev override](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides)
in `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "himitsu-io/himitsu" = "/path/to/integrations/terraform-provider"
  }
  direct {}
}
```

## Publishing

The published repository is
**[himitsu-io/terraform-provider-himitsu](https://github.com/himitsu-io/terraform-provider-himitsu)**
(public, MPL-2.0). The Terraform Registry requires a repository named exactly
`terraform-provider-himitsu`, which is why it lives outside this monorepo.

**Do not publish it with `git subtree split`.** The split would carry this
module's `require`/`replace` on
`github.com/sirsjg/himitsu-enterprise/integrations/client`, and because this
monorepo is private that dependency is unresolvable — for installers, and for
the Registry's own build. The published repository instead **vendors** the
client at `internal/himitsu/`.

To ship a change made here:

```sh
PUBLISHED=/path/to/terraform-provider-himitsu

cp internal/provider/*.go   "$PUBLISHED"/internal/provider/
cp main.go examples/main.tf "$PUBLISHED"/
cp ../client/*.go           "$PUBLISHED"/internal/himitsu/

cd "$PUBLISHED"
sed -i '' 's|^package client$|package himitsu|' internal/himitsu/*.go
sed -i '' 's|himitsu "github.com/sirsjg/himitsu-enterprise/integrations/client"|"github.com/himitsu-io/terraform-provider-himitsu/internal/himitsu"|' internal/provider/*.go
grep -rn himitsu-enterprise . --include='*.go'   # must print nothing
go mod tidy && go test ./...
tfplugindocs generate --provider-name himitsu    # refresh docs/
```

Releases are cut by tagging there (`git tag v0.1.0 && git push origin v0.1.0`).
GoReleaser builds every platform and signs the checksums; the repository needs
`GPG_PRIVATE_KEY` and `PASSPHRASE` secrets, with the matching public key
registered against the `himitsu-io` namespace on registry.terraform.io.

That namespace has not been claimed on registry.terraform.io yet, so the provider
is not installable by `source = "himitsu-io/himitsu"` until it is. Until then, use
`dev_overrides`.
