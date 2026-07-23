# REST API v1 reference

The generated [OpenAPI 3.1 document](openapi.json) is the authoritative contract for paths, methods, parameters, request bodies, response schemas, and operation IDs. A running API serves the same document from `GET /api/v1/openapi.json`. Regenerate the committed copy after route changes with `npm run docs:openapi`; `npm run docs:check` fails when it drifts.

## Protocol

- Base path: `/api/v1`
- Request and response media type: `application/json`
- Dates: ISO 8601 UTC timestamps
- IDs: UUIDs, except audit event IDs and opaque pagination cursors
- Secret values: returned only by explicit read, bulk-get, runtime, compare-with-reveal, and export operations
- Caching: API responses carry `Cache-Control: no-store`; runtime fetches additionally support ETags

Successful JSON responses use a data envelope:

```json
{
  "data": {},
  "meta": {
    "limit": 50,
    "offset": 0,
    "total": 1
  }
}
```

The `meta` object is present on paginated collection routes. Audit pagination uses `nextCursor` inside its data object.

Errors use a stable, non-secret envelope:

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Permission denied",
    "requestId": "req-1"
  }
}
```

Validation failures may include a `details` object. Do not build control flow from human-readable messages; use the status and `error.code`.

## Authentication

Browser clients send the host-only secure session cookie. Every unsafe session request also sends the readable CSRF cookie value in `X-CSRF-Token`:

```http
Cookie: __Host-himitsu_session=SESSION
X-CSRF-Token: CSRF_TOKEN
```

Machine clients use one bearer API key:

```http
Authorization: Bearer himi_PREFIX_SECRET
```

Do not combine cookie and bearer authentication. API keys can be organization-, project-, or project+environment-scoped and read-only or read-write. Route RBAC, project overrides, protected-environment rules, tenant RLS, credential scope, expiry, revocation, per-IP limits, and per-key limits are all enforced server-side.

Rate-limited responses return `429`, `Retry-After`, and standard `RateLimit-*` headers.

## Resource groups

The OpenAPI document contains the complete schemas. This index summarizes intent and sensitive behavior.

### Organization and members

- `GET|PATCH /organization` — inspect or update the active organization profile.
- `GET /members` — list active members.
- `PATCH|DELETE /members/{memberId}` — change a role or remove a member with owner/admin hierarchy protections.
- `GET|POST /invitations` — list pending invitations or invite a member.
- `DELETE /invitations/{invitationId}` — revoke a pending invitation.
- `GET|PATCH /audit-settings` — inspect or update audit retention.

Invitation tokens are delivered out of band and never returned by member-list APIs.

### Projects, environments, and tags

- `/projects` and `/projects/{projectId}` — paginated search, create, inspect, update, archive/delete lifecycle.
- `/projects/{projectId}/environments` — list and create environments.
- `/projects/{projectId}/environments/reorder` — atomically set display order.
- `/projects/{projectId}/environments/{environmentId}` — inspect, update, protect, or delete an environment.
- `/tags`, `/tags/{tagId}`, and `/tags/{tagId}/merge` — organization tag registry and reference-safe merge/delete.

Collection search examines metadata, never decrypted secret values.

### Secrets, versions, and promotion

- `/projects/{projectId}/environments/{environmentId}/secrets` — list metadata or create a value.
- `.../secrets/bulk` and `.../secrets/bulk-get` — atomic multi-key write and batched runtime read.
- `/secrets/{secretId}` — explicit value read, optimistic update with `If-Match`, or soft delete.
- `/secrets/{secretId}/versions` — immutable version metadata.
- `/secrets/{secretId}/versions/compare` — masked comparison by default; `reveal=true` explicitly returns values.
- `/secrets/{secretId}/versions/{version}/rollback` — create a new version from historical ciphertext.
- `.../promotions/preview` and `.../promotions` — preview and commit selected/all cross-environment copies.

Secret reads, writes, deletes, promotions, imports, exports, and runtime fetches are audit-logged without plaintext metadata.

### Import and export

- `.../imports/dotenv/preview` and `.../imports/dotenv` — parse/preview and commit dotenv.
- `.../imports/json/preview` and `.../imports/json` — flatten/preview and commit JSON.
- `.../exports?format=dotenv|json|shell` — audited plaintext export; JSON supports `nested=true` and a delimiter.

Use previews before committing human-supplied input. Export response bodies are plaintext and must not enter logs or shared caches.

### Runtime and consistency

- `GET .../secrets/runtime` — all values plus `configVersion` in one round trip. Send `If-None-Match`; unchanged configuration returns `304` with no body.
- `GET /projects/{projectId}/consistency` — value-free matrix, findings, counts, and an exit-code-friendly health summary.

Example runtime request:

```sh
curl --fail-with-body \
  --header "Authorization: Bearer $HIMITSU_TOKEN" \
  --header 'If-None-Match: "himi-config-42"' \
  "$HIMITSU_API_URL/api/v1/projects/$PROJECT_ID/environments/$ENVIRONMENT_ID/secrets/runtime"
```

### API keys and audit

- `GET|POST /api-keys` — list metadata or create a scoped credential. Plaintext appears only in the create response.
- `DELETE /api-keys/{apiKeyId}` — revoke a credential.
- `GET /audit-events` — administrator-only filtered cursor pagination.
- `GET /audit-events/export?format=csv|json` — filtered compliance export.

Audit filters include actor, action, project, environment, time range, and resource search. Audit metadata rejects secret-bearing field names and oversized structures.

## OpenAPI workflow

Build the API before generation so the route module is current:

```sh
npm run build --workspace @himitsu/api
npm run docs:openapi
npm run docs:check
```

The checker loads the generated contract from the compiled route definitions, compares it byte-for-byte with `docs/openapi.json`, validates required guide sections and local links, and rejects undocumented CLI commands.
