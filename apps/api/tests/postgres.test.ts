import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { TransactionalAuditLog } from "@himitsu/audit";
import { ApiKeyService } from "@himitsu/api-keys";
import { AuthService, sessionCookie } from "@himitsu/auth";
import { AuthorizationContextResolver } from "@himitsu/authz";
import { LocalMasterKey } from "@himitsu/crypto";
import { EnvironmentService } from "@himitsu/environments";
import { ProjectService } from "@himitsu/projects";
import { SecretService } from "@himitsu/secrets";
import { TenantDatabase } from "@himitsu/tenancy";
import { Pool } from "pg";
import { apiRoutePermissions, buildApi, securityHeaders } from "../src/index.js";

const adminConnectionString = process.env.TEST_DATABASE_URL;
const appConnectionString = process.env.TEST_APP_DATABASE_URL;
if (adminConnectionString === undefined || appConnectionString === undefined) {
  throw new Error("TEST_DATABASE_URL and TEST_APP_DATABASE_URL are required");
}

const adminPool = new Pool({ connectionString: adminConnectionString, max: 2 });
const appPool = new Pool({ connectionString: appConnectionString, max: 10 });
const database = new TenantDatabase(appPool);
const audit = new TransactionalAuditLog(appPool);
const auth = new AuthService(appPool, {
  async sendEmailVerification() {},
  async sendPasswordReset() {},
});
const resolver = new AuthorizationContextResolver();
const ownerA = randomUUID();
const memberA = randomUUID();
const readerA = randomUUID();
const ownerB = randomUUID();
const orgA = randomUUID();
const orgB = randomUUID();
const sessionTokens = new Map<string, { session: string; csrf: string }>([
  [ownerA, { session: `session-${randomUUID()}`, csrf: `csrf-${randomUUID()}` }],
  [memberA, { session: `session-${randomUUID()}`, csrf: `csrf-${randomUUID()}` }],
  [readerA, { session: `session-${randomUUID()}`, csrf: `csrf-${randomUUID()}` }],
  [ownerB, { session: `session-${randomUUID()}`, csrf: `csrf-${randomUUID()}` }],
]);
const revokedSessionToken = `session-${randomUUID()}`;
let otherOrgSecretId = "";
const projects = new ProjectService(resolver, audit);
const apiKeys = new ApiKeyService(appPool, resolver, audit);
const environments = new EnvironmentService(resolver, audit);
const secrets = new SecretService(
  resolver,
  audit,
  new LocalMasterKey("api-integration-v1", Buffer.alloc(32, 9)),
);
const app = await buildApi({
  database,
  auth,
  apiKeys,
  audit,
  projects,
  environments,
  secrets,
  rateLimits: { perIp: 1_000, perApiKey: 100 },
});

const digest = (value: string) => createHash("sha256").update(value, "utf8").digest();

const headers = (_orgId: string, userId: string) => {
  const credentials = sessionTokens.get(userId);
  assert.ok(credentials);
  return {
    cookie: `${sessionCookie.name}=${encodeURIComponent(credentials.session)}`,
    "x-csrf-token": credentials.csrf,
  };
};

before(async () => {
  await adminPool.query(
    `INSERT INTO users (id, email, email_verified_at) VALUES
      ($1, 'api-owner-a@example.com', now()), ($2, 'api-member-a@example.com', now()),
      ($3, 'api-reader-a@example.com', now()), ($4, 'api-owner-b@example.com', now())`,
    [ownerA, memberA, readerA, ownerB],
  );
  await adminPool.query(
    "INSERT INTO organizations (id, name, slug) VALUES ($1, 'API Alpha', 'api-alpha'), ($2, 'API Beta', 'api-beta')",
    [orgA, orgB],
  );
  await adminPool.query(
    `INSERT INTO memberships (org_id, user_id, role) VALUES
      ($1, $2, 'owner'), ($1, $3, 'member'), ($1, $4, 'read_only'), ($5, $6, 'owner')`,
    [orgA, ownerA, memberA, readerA, orgB, ownerB],
  );
  for (const [userId, orgId] of [[ownerA, orgA], [memberA, orgA], [readerA, orgA], [ownerB, orgB]] as const) {
    const credentials = sessionTokens.get(userId);
    assert.ok(credentials);
    await adminPool.query(
      `INSERT INTO sessions (user_id, token_hash, csrf_hash, active_org_id, expires_at)
       VALUES ($1, $2, $3, $4, now() + interval '1 day')`,
      [userId, digest(credentials.session), digest(credentials.csrf), orgId],
    );
  }
  await adminPool.query(
    `INSERT INTO sessions (user_id, token_hash, csrf_hash, active_org_id, expires_at, revoked_at)
     VALUES ($1, $2, $3, $4, now() + interval '1 day', now())`,
    [ownerA, digest(revokedSessionToken), digest("revoked-csrf"), orgA],
  );
  await database.withOrg(orgB, ownerB, async (transaction) => {
    const project = await projects.create(transaction, ownerB, {
      name: "Other Tenant Project",
      slug: "other-tenant-project",
    });
    const projectEnvironments = await environments.list(transaction, ownerB, project.id);
    const environment = projectEnvironments.find(({ slug }) => slug === "development");
    assert.ok(environment);
    const secret = await secrets.create(
      transaction,
      ownerB,
      project.id,
      environment.id,
      { key: "OTHER_TENANT_SECRET", value: "isolated" },
    );
    otherOrgSecretId = secret.id;
  });
});

after(async () => {
  await app.close();
  await appPool.end();
  await adminPool.end();
});

test("generates an OpenAPI 3.1 contract from every v1 route", async () => {
  const response = await app.inject({ method: "GET", url: "/api/v1/openapi.json" });
  assert.equal(response.statusCode, 200);
  const document = response.json() as {
    openapi: string;
    paths: Record<string, Record<string, { operationId?: string }>>;
  };
  assert.equal(document.openapi, "3.1.0");
  for (const [name, value] of Object.entries(securityHeaders)) {
    assert.equal(response.headers[name], value, `Security header missing: ${name}`);
  }
  for (const path of [
    "/api/v1/projects",
    "/api/v1/projects/{projectId}/environments",
    "/api/v1/projects/{projectId}/environments/{environmentId}/secrets/bulk-get",
    "/api/v1/secrets/{secretId}/versions",
    "/api/v1/tags",
    "/api/v1/api-keys",
  ]) assert.ok(document.paths[path], `OpenAPI path missing: ${path}`);
  const operationIds = Object.values(document.paths).flatMap((methods) =>
    Object.values(methods).map(({ operationId }) => operationId).filter(Boolean),
  );
  assert.equal(new Set(operationIds).size, operationIds.length);
  assert.deepEqual(
    new Set(operationIds.filter((operationId) => operationId !== "getOpenApi")),
    new Set(Object.keys(apiRoutePermissions)),
  );
  const projectCreate = document.paths["/api/v1/projects"]?.post as unknown as {
    responses: { "2XX": { content: { "application/json": { schema: { properties: { data: { properties: Record<string, unknown> } } } } } } };
  };
  assert.ok(projectCreate.responses["2XX"].content["application/json"].schema.properties.data.properties.id);
  const secretRead = document.paths["/api/v1/secrets/{secretId}"]?.get as unknown as {
    responses: { "2XX": { content: { "application/json": { schema: { properties: { data: { properties: Record<string, unknown> } } } } } } };
  };
  assert.ok(secretRead.responses["2XX"].content["application/json"].schema.properties.data.properties.value);
});

test("returns stable validation and authentication error envelopes", async () => {
  const unauthenticated = await app.inject({ method: "GET", url: "/api/v1/projects" });
  assert.equal(unauthenticated.statusCode, 401);
  assert.deepEqual(Object.keys(unauthenticated.json().error).sort(), ["code", "message", "requestId"]);
  assert.equal(unauthenticated.json().error.code, "UNAUTHENTICATED");
  assert.equal(unauthenticated.headers["ratelimit-limit"], "1000");

  const invalid = await app.inject({
    method: "POST",
    url: "/api/v1/projects",
    headers: headers(orgA, ownerA),
    payload: { slug: "missing-name" },
  });
  assert.equal(invalid.statusCode, 400);
  assert.equal(invalid.json().error.code, "INVALID_REQUEST");
  assert.ok(invalid.json().error.requestId);
});

test("enforces session CSRF and audits attributable failed authentication", async () => {
  const credentials = sessionTokens.get(ownerA);
  assert.ok(credentials);
  const missingCsrf = await app.inject({
    method: "POST",
    url: "/api/v1/projects",
    headers: { cookie: `${sessionCookie.name}=${encodeURIComponent(credentials.session)}` },
    payload: { name: "Denied", slug: "denied" },
  });
  assert.equal(missingCsrf.statusCode, 403);
  assert.equal(missingCsrf.json().error.code, "INVALID_CSRF");

  const revoked = await app.inject({
    method: "GET",
    url: "/api/v1/projects",
    headers: { cookie: `${sessionCookie.name}=${encodeURIComponent(revokedSessionToken)}` },
  });
  assert.equal(revoked.statusCode, 401);
  const failures = await database.withOrg(orgA, ownerA, (transaction) => transaction.query<{
    actor_type: string;
    resource_type: string;
    metadata: { details?: { method?: string; reason?: string } };
  }>(
    `SELECT actor_type, resource_type, metadata FROM audit_events
     WHERE action = 'auth.login_failed' ORDER BY id`,
  ));
  assert.deepEqual(failures.rows.map(({ actor_type, resource_type }) => ({ actor_type, resource_type })), [
    { actor_type: "user", resource_type: "session" },
    { actor_type: "user", resource_type: "session" },
  ]);
  assert.deepEqual(failures.rows.map(({ metadata }) => metadata.details), [
    { method: "session", reason: "INVALID_CSRF" },
    { method: "session", reason: "INVALID_SESSION" },
  ]);
});

test("enforces route policies for read-only users and RLS for cross-tenant secret IDs", async () => {
  const readerList = await app.inject({
    method: "GET", url: "/api/v1/projects", headers: headers(orgA, readerA),
  });
  assert.equal(readerList.statusCode, 200, readerList.body);
  const readerWrite = await app.inject({
    method: "POST", url: "/api/v1/projects", headers: headers(orgA, readerA),
    payload: { name: "Denied", slug: "reader-denied" },
  });
  assert.equal(readerWrite.statusCode, 403);
  assert.equal(readerWrite.json().error.code, "FORBIDDEN");
  const readerApiKeys = await app.inject({
    method: "GET", url: "/api/v1/api-keys", headers: headers(orgA, readerA),
  });
  assert.equal(readerApiKeys.statusCode, 403);

  const crossTenant = await app.inject({
    method: "GET", url: `/api/v1/secrets/${otherOrgSecretId}`, headers: headers(orgA, ownerA),
  });
  assert.equal(crossTenant.statusCode, 404, crossTenant.body);
  assert.equal(crossTenant.json().error.code, "NOT_FOUND");
  const tenantOwner = await app.inject({
    method: "GET", url: `/api/v1/secrets/${otherOrgSecretId}`, headers: headers(orgB, ownerB),
  });
  assert.equal(tenantOwner.statusCode, 200, tenantOwner.body);
  assert.equal(tenantOwner.json().data.value, "isolated");
});

let projectId: string;
let developmentId: string;
let productionId: string;
let secretId: string;
let tagId: string;

test("exposes paginated project, environment, and tag CRUD", async () => {
  const createdTag = await app.inject({
    method: "POST", url: "/api/v1/tags", headers: headers(orgA, ownerA),
    payload: { name: " database ", color: "#aabbcc" },
  });
  assert.equal(createdTag.statusCode, 201, createdTag.body);
  tagId = createdTag.json().data.id;
  assert.equal(createdTag.json().data.color, "#AABBCC");

  const createdProject = await app.inject({
    method: "POST", url: "/api/v1/projects", headers: headers(orgA, ownerA),
    payload: { name: "API Project", slug: "api-project", tagIds: [tagId] },
  });
  assert.equal(createdProject.statusCode, 201, createdProject.body);
  projectId = createdProject.json().data.id;
  assert.deepEqual(createdProject.json().data.tagIds, [tagId]);

  const listed = await app.inject({
    method: "GET", url: "/api/v1/projects?limit=1&offset=0", headers: headers(orgA, memberA),
  });
  assert.equal(listed.statusCode, 200, listed.body);
  assert.equal(listed.json().data.length, 1);
  assert.deepEqual(listed.json().meta, { limit: 1, offset: 0, total: 1 });

  const environmentList = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments`,
    headers: headers(orgA, memberA),
  });
  assert.equal(environmentList.statusCode, 200, environmentList.body);
  assert.deepEqual(environmentList.json().data.map(({ slug }: { slug: string }) => slug), [
    "development", "staging", "production",
  ]);
  developmentId = environmentList.json().data.find(({ slug }: { slug: string }) => slug === "development").id;
  productionId = environmentList.json().data.find(({ slug }: { slug: string }) => slug === "production").id;

  const custom = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments`,
    headers: headers(orgA, memberA),
    payload: { name: "Preview", slug: "preview" },
  });
  assert.equal(custom.statusCode, 201, custom.body);
  const ids = [custom.json().data.id, ...environmentList.json().data.map(({ id }: { id: string }) => id)];
  const reordered = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/reorder`,
    headers: headers(orgA, ownerA),
    payload: { environmentIds: ids },
  });
  assert.equal(reordered.statusCode, 200, reordered.body);
  assert.deepEqual(reordered.json().data.map(({ id }: { id: string }) => id), ids);

  const tags = await app.inject({ method: "GET", url: "/api/v1/tags?limit=1", headers: headers(orgA, memberA) });
  assert.equal(tags.statusCode, 200, tags.body);
  assert.equal(tags.json().meta.total, 1);
  const updatedTag = await app.inject({
    method: "PATCH", url: `/api/v1/tags/${tagId}`, headers: headers(orgA, ownerA),
    payload: { name: "datastore" },
  });
  assert.equal(updatedTag.statusCode, 200, updatedTag.body);
  assert.equal(updatedTag.json().data.name, "datastore");
});

test("exposes secret create, update, bulk set/get, delete, and version metadata", async () => {
  const created = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets`,
    headers: headers(orgA, memberA),
    payload: { key: "DATABASE_URL", value: "postgres://api-first", notes: "API test" },
  });
  assert.equal(created.statusCode, 201, created.body);
  secretId = created.json().data.id;
  assert.equal(created.json().data.currentVersion, 1);

  const updated = await app.inject({
    method: "PATCH", url: `/api/v1/secrets/${secretId}`, headers: headers(orgA, memberA),
    payload: { value: "postgres://api-second", changeNote: "API rotation" },
  });
  assert.equal(updated.statusCode, 200, updated.body);
  assert.equal(updated.json().data.currentVersion, 2);

  const bulkSet = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets/bulk`,
    headers: headers(orgA, memberA),
    payload: { secrets: [
      { key: "CACHE_URL", value: "redis://api" },
      { key: "FEATURE_FLAG", value: "on" },
    ] },
  });
  assert.equal(bulkSet.statusCode, 200, bulkSet.body);
  assert.equal(bulkSet.json().data.length, 2);

  const bulkGet = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets/bulk-get`,
    headers: headers(orgA, memberA),
    payload: { keys: ["DATABASE_URL", "FEATURE_FLAG"] },
  });
  assert.equal(bulkGet.statusCode, 200, bulkGet.body);
  assert.deepEqual(bulkGet.json().data, { DATABASE_URL: "postgres://api-second", FEATURE_FLAG: "on" });

  const versions = await app.inject({
    method: "GET", url: `/api/v1/secrets/${secretId}/versions?limit=1`, headers: headers(orgA, memberA),
  });
  assert.equal(versions.statusCode, 200, versions.body);
  assert.equal(versions.json().meta.total, 2);
  assert.equal(versions.json().data[0].version, 2);
  assert.equal(versions.json().data[0].current, true);
  assert.equal("value" in versions.json().data[0], false);

  const read = await app.inject({ method: "GET", url: `/api/v1/secrets/${secretId}`, headers: headers(orgA, memberA) });
  assert.equal(read.statusCode, 200, read.body);
  assert.equal(read.json().data.value, "postgres://api-second");

  const deleted = await app.inject({ method: "DELETE", url: `/api/v1/secrets/${secretId}`, headers: headers(orgA, memberA) });
  assert.equal(deleted.statusCode, 200, deleted.body);
  const missing = await app.inject({ method: "GET", url: `/api/v1/secrets/${secretId}`, headers: headers(orgA, memberA) });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.json().error.code, "NOT_FOUND");
});

test("maps RBAC and tenant isolation failures to non-leaking HTTP errors", async () => {
  const protectedWrite = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${productionId}/secrets`,
    headers: headers(orgA, memberA),
    payload: { key: "PROTECTED", value: "denied" },
  });
  assert.equal(protectedWrite.statusCode, 403, protectedWrite.body);
  assert.equal(protectedWrite.json().error.code, "FORBIDDEN");

  const crossTenant = await app.inject({
    method: "GET", url: `/api/v1/projects/${projectId}`, headers: headers(orgB, ownerB),
  });
  assert.equal(crossTenant.statusCode, 404, crossTenant.body);
  assert.equal(crossTenant.json().error.code, "NOT_FOUND");

  const memberTagWrite = await app.inject({
    method: "POST", url: "/api/v1/tags", headers: headers(orgA, memberA),
    payload: { name: "denied", color: "#112233" },
  });
  assert.equal(memberTagWrite.statusCode, 403);
});

test("manages scoped API keys while revealing token material only at creation", async () => {
  const created = await app.inject({
    method: "POST", url: "/api/v1/api-keys", headers: headers(orgA, ownerA),
    payload: {
      name: "API managed CI key",
      access: "read_write",
      projectId,
      environmentId: developmentId,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    },
  });
  assert.equal(created.statusCode, 201, created.body);
  assert.match(created.json().data.token, /^himi_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
  const apiKeyId = created.json().data.apiKey.id;

  const listed = await app.inject({ method: "GET", url: "/api/v1/api-keys?limit=1", headers: headers(orgA, ownerA) });
  assert.equal(listed.statusCode, 200, listed.body);
  assert.equal(listed.json().meta.total, 1);
  assert.equal("token" in listed.json().data[0], false);
  assert.equal(listed.body.includes(created.json().data.token), false);

  const denied = await app.inject({
    method: "POST", url: "/api/v1/api-keys", headers: headers(orgA, memberA),
    payload: { name: "Denied", access: "read_only" },
  });
  assert.equal(denied.statusCode, 403);

  const token = created.json().data.token as string;
  const machineRead = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets`,
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(machineRead.statusCode, 200, machineRead.body);
  assert.equal(machineRead.headers["ratelimit-limit"], "100");
  assert.ok(Number(machineRead.headers["ratelimit-remaining"]) < 100);

  const secondProject = await app.inject({
    method: "POST", url: "/api/v1/projects", headers: headers(orgA, ownerA),
    payload: { name: "Out of Scope Project", slug: "out-of-scope-project" },
  });
  assert.equal(secondProject.statusCode, 201, secondProject.body);
  const crossProjectKey = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${secondProject.json().data.id}`,
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(crossProjectKey.statusCode, 403, crossProjectKey.body);
  assert.equal(crossProjectKey.json().error.code, "API_SCOPE_FORBIDDEN");
  const crossTenantKey = await app.inject({
    method: "GET",
    url: `/api/v1/secrets/${otherOrgSecretId}`,
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(crossTenantKey.statusCode, 404, crossTenantKey.body);

  const machineWrite = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets`,
    headers: { authorization: `Bearer ${token}` },
    payload: { key: "MACHINE_WRITE", value: "allowed" },
  });
  assert.equal(machineWrite.statusCode, 201, machineWrite.body);

  const wrongEnvironment = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${productionId}/secrets`,
    headers: { authorization: `Bearer ${token}` },
    payload: { key: "OUT_OF_SCOPE", value: "denied" },
  });
  assert.equal(wrongEnvironment.statusCode, 403);
  assert.equal(wrongEnvironment.json().error.code, "API_SCOPE_FORBIDDEN");

  const scopedProjects = await app.inject({
    method: "GET", url: "/api/v1/projects", headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(scopedProjects.statusCode, 200, scopedProjects.body);
  assert.deepEqual(scopedProjects.json().data.map(({ id }: { id: string }) => id), [projectId]);
  const scopedTags = await app.inject({
    method: "GET", url: "/api/v1/tags", headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(scopedTags.statusCode, 403);

  const readOnlyCreated = await app.inject({
    method: "POST", url: "/api/v1/api-keys", headers: headers(orgA, ownerA),
    payload: { name: "Read-only runtime", access: "read_only", projectId, environmentId: developmentId },
  });
  assert.equal(readOnlyCreated.statusCode, 201, readOnlyCreated.body);
  const readOnlyToken = readOnlyCreated.json().data.token as string;
  const readOnlyGet = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets`,
    headers: { authorization: `Bearer ${readOnlyToken}` },
  });
  assert.equal(readOnlyGet.statusCode, 200, readOnlyGet.body);
  const readOnlyWrite = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets`,
    headers: { authorization: `Bearer ${readOnlyToken}` },
    payload: { key: "READ_ONLY_DENIED", value: "denied" },
  });
  assert.equal(readOnlyWrite.statusCode, 403);
  assert.equal(readOnlyWrite.json().error.code, "API_SCOPE_FORBIDDEN");

  const ambiguous = await app.inject({
    method: "GET",
    url: "/api/v1/projects",
    headers: { ...headers(orgA, ownerA), authorization: `Bearer ${token}` },
  });
  assert.equal(ambiguous.statusCode, 401);

  const invalidToken = `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;
  const invalid = await app.inject({
    method: "GET", url: "/api/v1/projects", headers: { authorization: `Bearer ${invalidToken}` },
  });
  assert.equal(invalid.statusCode, 401);
  const apiKeyFailures = await database.withOrg(orgA, ownerA, (transaction) => transaction.query<{
    actor_type: string;
    actor_api_key_id: string;
    metadata: { details?: { method?: string; reason?: string } };
  }>(
    `SELECT actor_type, actor_api_key_id, metadata FROM audit_events
     WHERE action = 'auth.login_failed' AND actor_type = 'api_key' ORDER BY id`,
  ));
  assert.equal(apiKeyFailures.rows.at(-1)?.actor_api_key_id, apiKeyId);
  assert.deepEqual(apiKeyFailures.rows.at(-1)?.metadata.details, {
    method: "bearer", reason: "invalid_or_inactive",
  });

  const limitedApp = await buildApi({
    database, auth, apiKeys, audit, projects, environments, secrets,
    rateLimits: { perIp: 100, perApiKey: 1 },
  });
  const firstLimited = await limitedApp.inject({
    method: "GET", url: `/api/v1/projects/${projectId}`, headers: { authorization: `Bearer ${token}` },
  });
  const secondLimited = await limitedApp.inject({
    method: "GET", url: `/api/v1/projects/${projectId}`, headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(firstLimited.statusCode, 200, firstLimited.body);
  assert.equal(firstLimited.headers["ratelimit-remaining"], "0");
  assert.equal(secondLimited.statusCode, 429, secondLimited.body);
  assert.equal(secondLimited.headers["retry-after"], "60");
  await limitedApp.close();

  const revoked = await app.inject({
    method: "DELETE", url: `/api/v1/api-keys/${apiKeyId}`, headers: headers(orgA, ownerA),
  });
  assert.equal(revoked.statusCode, 200, revoked.body);
  assert.ok(revoked.json().data.revokedAt);
  const readOnlyRevoked = await app.inject({
    method: "DELETE",
    url: `/api/v1/api-keys/${readOnlyCreated.json().data.apiKey.id}`,
    headers: headers(orgA, ownerA),
  });
  assert.equal(readOnlyRevoked.statusCode, 200, readOnlyRevoked.body);
  const deletedSecondProject = await app.inject({
    method: "DELETE",
    url: `/api/v1/projects/${secondProject.json().data.id}`,
    headers: headers(orgA, ownerA),
  });
  assert.equal(deletedSecondProject.statusCode, 200, deletedSecondProject.body);
});

test("deletes tags and projects through their v1 lifecycle endpoints", async () => {
  const deletedTag = await app.inject({
    method: "DELETE", url: `/api/v1/tags/${tagId}`, headers: headers(orgA, ownerA),
  });
  assert.equal(deletedTag.statusCode, 200, deletedTag.body);
  const deletedProject = await app.inject({
    method: "DELETE", url: `/api/v1/projects/${projectId}`, headers: headers(orgA, ownerA),
  });
  assert.equal(deletedProject.statusCode, 200, deletedProject.body);
  assert.ok(deletedProject.json().data.deletedAt);
});
