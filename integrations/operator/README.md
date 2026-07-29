# Himitsu Kubernetes operator

Syncs a Himitsu environment into a Kubernetes Secret and keeps it current.

## Install

```sh
kubectl apply -f config/crd/himitsu.io_himitsusecrets.yaml
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/manager/manager.yaml
```

## Use

Create a Secret holding a read-only, environment-scoped Himitsu token, then a
`HimitsuSecret` describing the sync:

```sh
kubectl -n apps create secret generic himitsu-token --from-literal=token=himi_...
```

```yaml
apiVersion: himitsu.io/v1alpha1
kind: HimitsuSecret
metadata:
  name: app-config
  namespace: apps
spec:
  apiUrl: https://himitsu.example.com
  projectId: 11111111-1111-1111-1111-111111111111
  environmentId: 22222222-2222-2222-2222-222222222222
  authSecretRef:
    name: himitsu-token
  refreshInterval: 1m
  target:
    name: app-secrets
```

```sh
$ kubectl -n apps get hsec
NAME         SECRET        KEYS   VERSION   READY   LAST SYNC   AGE
app-config   app-secrets   14     37        True    12s         4m
```

Consume it the usual way:

```yaml
envFrom:
  - secretRef:
      name: app-secrets
```

See [`config/samples/himitsusecret.yaml`](config/samples/himitsusecret.yaml) for
the Dotenv and Merge variants.

## How syncing works

Each reconcile sends a conditional request carrying the config version last
written. In steady state the API answers `304 Not Modified`, so no secret
material crosses the network and no `secret.read` audit event is recorded. A
`refreshInterval` of `1m` is therefore cheap.

A full fetch is forced whenever a conditional request would be unsafe:

- the target Secret is missing (someone deleted it);
- its `himitsu.io/config-version` annotation does not match observed status
  (someone edited it);
- the spec changed since the status was written (now pointing at a different
  environment).

Without those checks a deleted Secret would never be restored — the operator
would keep receiving 304 and conclude everything was fine.

## Reference

### `spec`

| Field | Default | Notes |
| --- | --- | --- |
| `apiUrl` | — | Base URL of the Himitsu API. |
| `projectId` / `environmentId` | — | Himitsu UUIDs. |
| `authSecretRef.name` / `.key` | `.key: token` | Secret holding the API token, in the same namespace. |
| `refreshInterval` | `1m` | Poll cadence. `0` syncs once and stops. |
| `target.name` | — | Secret to create or maintain. |
| `target.type` | `Opaque` | Any Kubernetes Secret type. |
| `target.creationPolicy` | `Owner` | `Owner` or `Merge`, below. |
| `target.template.format` | `KeyValue` | `KeyValue`, `Dotenv`, or `Json`. |
| `target.template.key` | `.env` / `config.json` | Data key for the single-blob formats. |
| `target.template.labels` / `.annotations` | — | Merged onto the target. |

Cross-namespace `authSecretRef` is deliberately unsupported: it would let any
namespace owner mount a token they were never granted.

### Creation policies

**`Owner`** (default) — the operator is the sole author. It sets a controller
reference, so deleting the `HimitsuSecret` garbage collects the Secret, and a key
removed in Himitsu disappears from the Secret.

**`Merge`** — the operator patches its keys into a Secret owned by something
else. Foreign keys are never touched. Keys the operator previously wrote and that
Himitsu no longer has are removed, tracked via the `himitsu.io/managed-keys`
annotation. No controller reference is set, so the Secret outlives the
`HimitsuSecret`.

### Template formats

`KeyValue` writes one Secret data entry per Himitsu secret — the form `envFrom`
consumes. Kubernetes only permits `[A-Za-z0-9._-]` in data keys; if Himitsu holds
a key outside that set, the sync fails loudly with `Ready=False` and
`Reason=InvalidSpec` rather than writing a Secret that is quietly missing entries.
Use `Dotenv` or `Json` for such keys.

`Dotenv` and `Json` render everything into one data key. Both are deterministic
(sorted keys, escaped values), so a reconcile that changes nothing does not churn
the Secret's `resourceVersion`.

### Status

`Ready` carries the outcome. Reasons: `Synced`, `AuthenticationFailure`,
`FetchFailure`, `WriteFailure`, `InvalidSpec`, `TargetConflict`.

```sh
kubectl -n apps describe hsec app-config
```

`TargetConflict` means two `HimitsuSecret` resources name the same target. The
operator refuses to fight over it and leaves the incumbent alone.

## Running more than one replica

Pass `--leader-elect`. Without it, replicas will race to write the same Secrets.
`--namespace <ns>` restricts the operator to one namespace, letting it run with a
Role instead of a ClusterRole.

## Build

The Docker build context is `integrations/`, because this module depends on
`../client`:

```sh
cd integrations
docker build -f operator/Dockerfile -t ghcr.io/sirsjg/himitsu-operator:latest .
```
