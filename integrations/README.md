# Himitsu integrations

Three ways to consume Himitsu secrets from outside the CLI, plus the Go client they share.

| Directory | What it is | Language |
| --- | --- | --- |
| [`client/`](client) | Go SDK for the REST API v1 | Go |
| [`operator/`](operator) | Kubernetes operator syncing environments into Secrets | Go |
| [`github-action/`](github-action) | GitHub Action loading secrets into a workflow | TypeScript |
| [`terraform-provider/`](terraform-provider) | Terraform provider for projects, environments, secrets, tags, keys | Go |

## Why a shared client

All three need the same three behaviours from the API, and none of them agree on
these by accident:

- the `{"data": …}` success envelope and `{"error": {code, message, requestId}}` failure envelope;
- the ETag / `X-Himitsu-Config-Version` protocol on `GET …/secrets/runtime`, which
  makes a steady-state poll a 304 that transfers no secret material and records
  no audit read;
- retry policy — 429 and 5xx are retried with jittered backoff honouring
  `RateLimit-Reset`; 4xx is not, because retrying only burns rate-limit budget.

Keeping that in one module means an API change is fixed once.

## Layout

The Go code is three modules, not one, so the operator's Kubernetes dependency
tree stays out of the Terraform provider:

```
integrations/
  go.work                  # local development across all three
  client/go.mod
  operator/go.mod          # replace → ../client
  terraform-provider/go.mod  # replace → ../client
```

`go.work` is a convenience for local edits. Each module also carries its own
`replace` directive, so `GOWORK=off go build ./...` works — which is what CI and
the Docker build use.

## Development

```sh
cd integrations

# Go modules
(cd client && go test ./...)
(cd operator && go test ./...)
(cd terraform-provider && go test ./...)

# GitHub Action
(cd github-action && npm test && npm run build)
```

Regenerating the operator's CRD, RBAC, and deepcopy code after changing
`operator/api/v1alpha1/`:

```sh
go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
cd operator
controller-gen object paths=./api/...
controller-gen crd rbac:roleName=himitsu-operator paths=./... \
  output:crd:artifacts:config=config/crd \
  output:rbac:artifacts:config=config/rbac
```

## Choosing a token

Every integration authenticates with a Himitsu API key. Scope it as tightly as
the job allows:

| Integration | Recommended scope |
| --- | --- |
| Operator | `read_only`, environment-scoped — it never writes back |
| GitHub Action | `read_only`, environment-scoped |
| Terraform provider | `read_write`, project-scoped or organization-wide, since it creates resources |

> An API key's effective permissions follow the Himitsu membership of the user
> whose credentials created it (`packages/api-keys/src/index.ts:318`). If that
> person is removed or demoted, tokens they minted change behaviour with them.
> Create long-lived automation tokens from an account you intend to keep.
