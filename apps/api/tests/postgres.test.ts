import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { TransactionalAuditLog } from "@himitsu/audit";
import { ApiKeyService } from "@himitsu/api-keys";
import { AuthService, sessionCookie } from "@himitsu/auth";
import { AuthorizationContextResolver } from "@himitsu/authz";
import { LocalMasterKey } from "@himitsu/crypto";
import { ConsistencyService } from "@himitsu/consistency";
import { EnvironmentService } from "@himitsu/environments";
import { ProjectService } from "@himitsu/projects";
import { SecretService } from "@himitsu/secrets";
import { TenantDatabase, TenancyService } from "@himitsu/tenancy";
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
const deliveredInvitations: Array<{ email: string; token: string }> = [];
const tenancy = new TenancyService(database, {
  async sendOrganizationInvitation({ email, token }) { deliveredInvitations.push({ email, token }); },
}, audit);
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
const consistency = new ConsistencyService(resolver, secrets, audit);
const app = await buildApi({
  database,
  tenancy,
  auth,
  apiKeys,
  audit,
  projects,
  environments,
  secrets,
  consistency,
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
    "/api/v1/cli/login",
    "/api/v1/projects/{projectId}/environments",
    "/api/v1/projects/{projectId}/consistency",
    "/api/v1/audit-events",
    "/api/v1/audit-events/export",
    "/api/v1/audit-settings",
    "/api/v1/projects/{projectId}/environments/{environmentId}/secrets/bulk-get",
    "/api/v1/projects/{projectId}/environments/{environmentId}/promotions/preview",
    "/api/v1/projects/{projectId}/environments/{environmentId}/promotions",
    "/api/v1/secrets/{secretId}/versions",
    "/api/v1/tags",
    "/api/v1/api-keys",
    "/api/v1/organization",
    "/api/v1/members",
    "/api/v1/invitations",
  ]) assert.ok(document.paths[path], `OpenAPI path missing: ${path}`);
  const operationIds = Object.values(document.paths).flatMap((methods) =>
    Object.values(methods).map(({ operationId }) => operationId).filter(Boolean),
  );
  assert.equal(new Set(operationIds).size, operationIds.length);

  /**
   * Routes that run outside tenant authorization, and so carry no entry in
   * apiRoutePermissions: they either establish a session or act before one has
   * an active organization.
   *
   * Listing them explicitly keeps the invariant below meaningful. Every other
   * route must have a permission, because enforceRoutePermission fails closed
   * with AUTHORIZATION_POLICY_MISSING when one is absent — so a new tenant
   * route that forgets its policy has to fail here rather than in production.
   */
  const sessionScopedOperations = new Set([
    "acceptInvitation",
    "confirmPasswordReset",
    "createOrganization",
    "getSession",
    "login",
    "logout",
    "requestPasswordReset",
    "resendVerification",
    "signup",
    "switchOrganization",
    "verifyEmail",
  ]);
  assert.deepEqual(
    new Set(operationIds.filter((operationId): operationId is string =>
      operationId !== undefined
      && operationId !== "getOpenApi"
      && !sessionScopedOperations.has(operationId))),
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

test("creates a CLI session and selects its sole organization", async () => {
  const email = `cli-${randomUUID()}@example.com`;
  const registered = await auth.signup(email, "correct horse battery staple");
  await adminPool.query("UPDATE users SET email_verified_at = now() WHERE id = $1", [registered.userId]);
  await adminPool.query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'admin')", [orgA, registered.userId]);
  const login = await app.inject({
    method: "POST", url: "/api/v1/cli/login", payload: { email, password: "correct horse battery staple" },
  });
  assert.equal(login.statusCode, 200, login.body);
  assert.equal(login.json().data.activeOrgId, orgA);
  assert.equal(login.json().data.organizations.length, 1);
  assert.ok(login.json().data.sessionToken);
  assert.ok(login.json().data.csrfToken);
  const authenticated = await app.inject({
    method: "GET", url: "/api/v1/projects",
    headers: { cookie: `${sessionCookie.name}=${encodeURIComponent(login.json().data.sessionToken)}` },
  });
  assert.equal(authenticated.statusCode, 200, authenticated.body);
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

test("manages organization profile, members, invitations, and role safety", async () => {
  const organization = await app.inject({ method: "GET", url: "/api/v1/organization", headers: headers(orgA, readerA) });
  assert.equal(organization.statusCode, 200, organization.body);
  assert.equal(organization.json().data.slug, "api-alpha");
  assert.equal(organization.json().data.retentionDays, 90);

  const deniedProfile = await app.inject({
    method: "PATCH", url: "/api/v1/organization", headers: headers(orgA, memberA),
    payload: { name: "Denied" },
  });
  assert.equal(deniedProfile.statusCode, 403, deniedProfile.body);
  const updatedProfile = await app.inject({
    method: "PATCH", url: "/api/v1/organization", headers: headers(orgA, ownerA),
    payload: { name: "API Alpha Settings", slug: "api-alpha-settings" },
  });
  assert.equal(updatedProfile.statusCode, 200, updatedProfile.body);
  assert.equal(updatedProfile.json().data.name, "API Alpha Settings");

  const members = await app.inject({ method: "GET", url: "/api/v1/members", headers: headers(orgA, readerA) });
  assert.equal(members.statusCode, 200, members.body);
  assert.ok(members.json().data.length >= 3);
  assert.equal(members.json().data.find(({ userId }: { userId: string }) => userId === ownerA).role, "owner");

  const changedRole = await app.inject({
    method: "PATCH", url: `/api/v1/members/${memberA}`, headers: headers(orgA, ownerA),
    payload: { role: "read_only" },
  });
  assert.equal(changedRole.statusCode, 200, changedRole.body);
  assert.equal(changedRole.json().data.role, "read_only");
  const ownerProtected = await app.inject({
    method: "DELETE", url: `/api/v1/members/${ownerA}`, headers: headers(orgA, ownerA),
  });
  assert.equal(ownerProtected.statusCode, 400, ownerProtected.body);
  assert.equal(ownerProtected.json().error.code, "SELF_REMOVAL_FORBIDDEN");
  const restoredRole = await app.inject({
    method: "PATCH", url: `/api/v1/members/${memberA}`, headers: headers(orgA, ownerA),
    payload: { role: "member" },
  });
  assert.equal(restoredRole.statusCode, 200, restoredRole.body);

  const removableUser = randomUUID();
  await adminPool.query("INSERT INTO users (id, email, email_verified_at) VALUES ($1, 'removable@example.com', now())", [removableUser]);
  await adminPool.query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'member')", [orgA, removableUser]);
  const removed = await app.inject({
    method: "DELETE", url: `/api/v1/members/${removableUser}`, headers: headers(orgA, ownerA),
  });
  assert.equal(removed.statusCode, 200, removed.body);
  assert.equal(removed.json().data.email, "removable@example.com");

  const deniedInvite = await app.inject({
    method: "POST", url: "/api/v1/invitations", headers: headers(orgA, readerA),
    payload: { email: "pending@example.com", role: "member" },
  });
  assert.equal(deniedInvite.statusCode, 403, deniedInvite.body);
  const invited = await app.inject({
    method: "POST", url: "/api/v1/invitations", headers: headers(orgA, ownerA),
    payload: { email: "Pending@Example.com", role: "read_only" },
  });
  assert.equal(invited.statusCode, 201, invited.body);
  assert.deepEqual(invited.json().data, { email: "pending@example.com", role: "read_only" });
  assert.equal(deliveredInvitations.at(-1)?.email, "pending@example.com");
  const invitations = await app.inject({ method: "GET", url: "/api/v1/invitations", headers: headers(orgA, readerA) });
  assert.equal(invitations.statusCode, 200, invitations.body);
  assert.equal(invitations.json().data.length, 1);
  assert.equal("token" in invitations.json().data[0], false);
  const revoked = await app.inject({
    method: "DELETE", url: `/api/v1/invitations/${invitations.json().data[0].id}`, headers: headers(orgA, ownerA),
  });
  assert.equal(revoked.statusCode, 200, revoked.body);

  const restoredProfile = await app.inject({
    method: "PATCH", url: "/api/v1/organization", headers: headers(orgA, ownerA),
    payload: { name: "API Alpha", slug: "api-alpha" },
  });
  assert.equal(restoredProfile.statusCode, 200, restoredProfile.body);
  const evidence = await database.withOrg(orgA, ownerA, (transaction) => transaction.query<{ action: string }>(
    `SELECT action FROM audit_events WHERE action IN
      ('organization.updated', 'membership.role_changed', 'membership.removed', 'membership.invited', 'membership.invitation_revoked')
     ORDER BY id`,
  ));
  assert.deepEqual(evidence.rows.map(({ action }) => action), [
    "organization.updated", "membership.role_changed", "membership.role_changed", "membership.removed",
    "membership.invited", "membership.invitation_revoked", "organization.updated",
  ]);
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
    method: "PATCH", url: `/api/v1/secrets/${secretId}`, headers: { ...headers(orgA, memberA), "if-match": '"1"' },
    payload: { value: "postgres://api-second", changeNote: "API rotation" },
  });
  assert.equal(updated.statusCode, 200, updated.body);
  assert.equal(updated.json().data.currentVersion, 2);

  const maskedComparison = await app.inject({
    method: "GET", url: `/api/v1/secrets/${secretId}/versions/compare?from=1&to=2`, headers: headers(orgA, memberA),
  });
  assert.equal(maskedComparison.statusCode, 200, maskedComparison.body);
  assert.deepEqual(maskedComparison.json().data, { fromVersion: 1, toVersion: 2, changed: true, masked: true });
  assert.equal(maskedComparison.body.includes("postgres://"), false);
  const revealedComparison = await app.inject({
    method: "GET", url: `/api/v1/secrets/${secretId}/versions/compare?from=1&to=2&reveal=true`, headers: headers(orgA, memberA),
  });
  assert.equal(revealedComparison.statusCode, 200, revealedComparison.body);
  assert.equal(revealedComparison.json().data.fromValue, "postgres://api-first");
  assert.equal(revealedComparison.json().data.toValue, "postgres://api-second");

  const staleUpdate = await app.inject({
    method: "PATCH", url: `/api/v1/secrets/${secretId}`, headers: { ...headers(orgA, memberA), "if-match": '"1"' },
    payload: { value: "postgres://stale-write" },
  });
  assert.equal(staleUpdate.statusCode, 409, staleUpdate.body);
  assert.equal(staleUpdate.json().error.code, "VERSION_CONFLICT");

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

  const runtime = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets/runtime`,
    headers: headers(orgA, memberA),
  });
  assert.equal(runtime.statusCode, 200, runtime.body);
  assert.ok(Number.isInteger(runtime.json().data.configVersion));
  assert.deepEqual(runtime.json().data.secrets, {
    CACHE_URL: "redis://api",
    DATABASE_URL: "postgres://api-second",
    FEATURE_FLAG: "on",
  });
  const runtimeEtag = runtime.headers.etag;
  assert.match(runtimeEtag ?? "", /^"himi-config-\d+"$/);
  assert.equal(runtime.headers["x-himitsu-config-version"], String(runtime.json().data.configVersion));
  assert.equal(runtime.headers["cache-control"], "no-store");
  const unchangedRuntime = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets/runtime`,
    headers: { ...headers(orgA, memberA), "if-none-match": `W/${runtimeEtag}` },
  });
  assert.equal(unchangedRuntime.statusCode, 304, unchangedRuntime.body);
  assert.equal(unchangedRuntime.body, "");
  assert.equal(unchangedRuntime.headers.etag, runtimeEtag);

  const rollback = await app.inject({
    method: "POST",
    url: `/api/v1/secrets/${secretId}/versions/1/rollback`,
    headers: headers(orgA, memberA),
    payload: { expectedVersion: 2, changeNote: "API rollback" },
  });
  assert.equal(rollback.statusCode, 200, rollback.body);
  assert.equal(rollback.json().data.currentVersion, 3);
  const changedRuntime = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets/runtime`,
    headers: { ...headers(orgA, memberA), "if-none-match": runtimeEtag },
  });
  assert.equal(changedRuntime.statusCode, 200, changedRuntime.body);
  assert.ok(changedRuntime.json().data.configVersion > runtime.json().data.configVersion);
  assert.equal(changedRuntime.json().data.secrets.DATABASE_URL, "postgres://api-first");

  const nestedExportSecret = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets`,
    headers: headers(orgA, memberA),
    payload: { key: "DATABASE__HOST", value: "db.internal", allowNonConformingKey: true },
  });
  assert.equal(nestedExportSecret.statusCode, 201, nestedExportSecret.body);

  const dotenvExport = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/exports?format=dotenv`,
    headers: headers(orgA, readerA),
  });
  assert.equal(dotenvExport.statusCode, 200, dotenvExport.body);
  assert.equal(dotenvExport.json().data.format, "dotenv");
  assert.equal(dotenvExport.json().data.filename, "api-project-development.env");
  assert.match(dotenvExport.json().data.content, /^CACHE_URL="redis:\/\/api"/);
  assert.equal(dotenvExport.json().data.secretCount, 4);
  const flatJsonExport = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/exports?format=json`,
    headers: headers(orgA, readerA),
  });
  assert.equal(flatJsonExport.statusCode, 200, flatJsonExport.body);
  assert.equal(JSON.parse(flatJsonExport.json().data.content).DATABASE__HOST, "db.internal");
  const nestedJsonExport = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/exports?format=json&nested=true&delimiter=__`,
    headers: headers(orgA, readerA),
  });
  assert.equal(nestedJsonExport.statusCode, 200, nestedJsonExport.body);
  assert.equal(JSON.parse(nestedJsonExport.json().data.content).DATABASE.HOST, "db.internal");
  assert.equal(nestedJsonExport.json().data.nested, true);
  const shellExport = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/exports?format=shell`,
    headers: headers(orgA, readerA),
  });
  assert.equal(shellExport.statusCode, 200, shellExport.body);
  assert.match(shellExport.json().data.content, /^export CACHE_URL='redis:\/\/api'/);
  assert.equal(shellExport.body.includes("\"value\":"), false);
  const exportAudits = await database.withOrg(orgA, ownerA, (transaction) => transaction.query<{
    actor_type: string;
    metadata: { details?: { format?: string; nested?: boolean; count?: number } };
  }>("SELECT actor_type, metadata FROM audit_events WHERE action = 'secret.exported' ORDER BY id"));
  assert.deepEqual(exportAudits.rows.map(({ metadata }) => metadata.details?.format), ["dotenv", "json", "json", "shell"]);
  assert.equal(exportAudits.rows.every(({ actor_type }) => actor_type === "user"), true);
  assert.equal(exportAudits.rows[2]?.metadata.details?.nested, true);
  assert.equal(exportAudits.rows.every(({ metadata }) => metadata.details?.count === 4), true);
  assert.equal(JSON.stringify(exportAudits.rows).includes("postgres://"), false);
  const deletedNestedExportSecret = await app.inject({
    method: "DELETE",
    url: `/api/v1/secrets/${nestedExportSecret.json().data.id}`,
    headers: headers(orgA, memberA),
  });
  assert.equal(deletedNestedExportSecret.statusCode, 200, deletedNestedExportSecret.body);
  const staleRollback = await app.inject({
    method: "POST",
    url: `/api/v1/secrets/${secretId}/versions/1/rollback`,
    headers: headers(orgA, memberA),
    payload: { expectedVersion: 2 },
  });
  assert.equal(staleRollback.statusCode, 409, staleRollback.body);
  assert.equal(staleRollback.json().error.code, "VERSION_CONFLICT");

  const versions = await app.inject({
    method: "GET", url: `/api/v1/secrets/${secretId}/versions?limit=1`, headers: headers(orgA, memberA),
  });
  assert.equal(versions.statusCode, 200, versions.body);
  assert.equal(versions.json().meta.total, 3);
  assert.equal(versions.json().data[0].version, 3);
  assert.equal(versions.json().data[0].current, true);
  assert.equal("value" in versions.json().data[0], false);

  const read = await app.inject({ method: "GET", url: `/api/v1/secrets/${secretId}`, headers: headers(orgA, memberA) });
  assert.equal(read.statusCode, 200, read.body);
  assert.equal(read.json().data.value, "postgres://api-first");

  const deleted = await app.inject({ method: "DELETE", url: `/api/v1/secrets/${secretId}`, headers: headers(orgA, memberA) });
  assert.equal(deleted.statusCode, 200, deleted.body);
  const missing = await app.inject({ method: "GET", url: `/api/v1/secrets/${secretId}`, headers: headers(orgA, memberA) });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.json().error.code, "NOT_FOUND");
});

test("attaches, searches, filters, merges, and deletes tags without breaking references", async () => {
  const otherOrgTag = await app.inject({
    method: "POST", url: "/api/v1/tags", headers: headers(orgB, ownerB),
    payload: { name: "other-tenant", color: "#111827" },
  });
  assert.equal(otherOrgTag.statusCode, 201, otherOrgTag.body);
  const crossTenantAttach = await app.inject({
    method: "POST", url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets`,
    headers: headers(orgA, memberA),
    payload: { key: "CROSS_TENANT_TAG", value: "never-written", tagIds: [otherOrgTag.json().data.id] },
  });
  assert.equal(crossTenantAttach.statusCode, 400, crossTenantAttach.body);
  assert.equal(crossTenantAttach.json().error.code, "TAG_NOT_FOUND");

  const sourceTag = await app.inject({
    method: "POST", url: "/api/v1/tags", headers: headers(orgA, ownerA),
    payload: { name: "pci-legacy", color: "#7C3AED" },
  });
  assert.equal(sourceTag.statusCode, 201, sourceTag.body);
  const sourceTagId = sourceTag.json().data.id as string;

  const taggedProject = await app.inject({
    method: "PATCH", url: `/api/v1/projects/${projectId}`, headers: headers(orgA, ownerA),
    payload: { tagIds: [sourceTagId] },
  });
  assert.equal(taggedProject.statusCode, 200, taggedProject.body);
  assert.equal(taggedProject.json().data.tags[0].name, "pci-legacy");

  const taggedSecret = await app.inject({
    method: "POST", url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets`,
    headers: headers(orgA, memberA),
    payload: { key: "TAGGED_CREDENTIAL", value: "tagged-value", tagIds: [sourceTagId] },
  });
  assert.equal(taggedSecret.statusCode, 201, taggedSecret.body);
  assert.deepEqual(taggedSecret.json().data.tagIds, [sourceTagId]);
  assert.equal(taggedSecret.json().data.tags[0].name, "pci-legacy");

  const projectFilter = await app.inject({
    method: "GET", url: `/api/v1/projects?tagId=${sourceTagId}&search=pci`, headers: headers(orgA, memberA),
  });
  assert.equal(projectFilter.statusCode, 200, projectFilter.body);
  assert.deepEqual(projectFilter.json().data.map(({ id }: { id: string }) => id), [projectId]);
  const secretFilter = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets?tagId=${sourceTagId}&search=legacy`,
    headers: headers(orgA, memberA),
  });
  assert.equal(secretFilter.statusCode, 200, secretFilter.body);
  assert.deepEqual(secretFilter.json().data.map(({ key }: { key: string }) => key), ["TAGGED_CREDENTIAL"]);

  const merged = await app.inject({
    method: "POST", url: `/api/v1/tags/${sourceTagId}/merge`, headers: headers(orgA, ownerA),
    payload: { targetTagId: tagId },
  });
  assert.equal(merged.statusCode, 200, merged.body);
  assert.equal(merged.json().data.id, tagId);
  const projectAfterMerge = await app.inject({
    method: "GET", url: `/api/v1/projects/${projectId}`, headers: headers(orgA, memberA),
  });
  assert.deepEqual(projectAfterMerge.json().data.tagIds, [tagId]);
  const secretsAfterMerge = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets?tagId=${tagId}&search=TAGGED`,
    headers: headers(orgA, memberA),
  });
  assert.deepEqual(secretsAfterMerge.json().data[0].tagIds, [tagId]);
  assert.equal(secretsAfterMerge.json().data[0].tags[0].name, "datastore");

});

test("returns a value-free consistency matrix and exit-code-friendly summary", async () => {
  const empty = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets`,
    headers: headers(orgA, memberA),
    payload: { key: "EMPTY_FOR_CHECK", value: "" },
  });
  assert.equal(empty.statusCode, 201, empty.body);

  const response = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/consistency`,
    headers: headers(orgA, readerA),
  });
  assert.equal(response.statusCode, 200, response.body);
  assert.equal(response.json().data.summary.healthy, false);
  assert.equal(response.json().data.summary.exitCode, 1);
  assert.ok(response.json().data.summary.activeFindings > 0);
  assert.equal(response.json().data.environments.length, 4);
  const row = response.json().data.matrix.find(({ key }: { key: string }) => key === "EMPTY_FOR_CHECK");
  assert.ok(row);
  assert.equal(row.cells.find(({ environmentId }: { environmentId: string }) => environmentId === developmentId).state, "empty");
  assert.equal(row.cells.filter(({ state }: { state: string }) => state === "missing").length, 3);
  assert.doesNotMatch(response.body, /postgres:\/\/api|first-import-value|dotenv-update/);

  const otherTenant = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/consistency`,
    headers: headers(orgB, ownerB),
  });
  assert.equal(otherTenant.statusCode, 404, otherTenant.body);
});

test("provides admin-only filtered audit browsing, export, and retention settings", async () => {
  const denied = await app.inject({ method: "GET", url: "/api/v1/audit-events", headers: headers(orgA, memberA) });
  assert.equal(denied.statusCode, 403, denied.body);

  const first = await app.inject({
    method: "GET",
    url: `/api/v1/audit-events?limit=1&actor=${encodeURIComponent("api-owner-a@example.com")}`,
    headers: headers(orgA, ownerA),
  });
  assert.equal(first.statusCode, 200, first.body);
  assert.equal(first.json().data.events.length, 1);
  assert.ok(first.json().data.nextCursor);
  assert.equal(first.body.includes("postgres://"), false);
  const second = await app.inject({
    method: "GET",
    url: `/api/v1/audit-events?limit=1&cursor=${encodeURIComponent(first.json().data.nextCursor)}`,
    headers: headers(orgA, ownerA),
  });
  assert.equal(second.statusCode, 200, second.body);
  assert.notEqual(second.json().data.events[0]?.id, first.json().data.events[0].id);

  const filtered = await app.inject({
    method: "GET",
    url: `/api/v1/audit-events?action=secret.created&projectId=${projectId}&environmentId=${developmentId}&resource=${secretId}`,
    headers: headers(orgA, ownerA),
  });
  assert.equal(filtered.statusCode, 200, filtered.body);
  assert.ok(filtered.json().data.events.length >= 1);
  assert.equal(filtered.json().data.events.every((event: { action: string }) => event.action === "secret.created"), true);
  const future = await app.inject({
    method: "GET", url: "/api/v1/audit-events?from=2100-01-01T00%3A00%3A00.000Z", headers: headers(orgA, ownerA),
  });
  assert.equal(future.statusCode, 200, future.body);
  assert.deepEqual(future.json().data.events, []);

  const csv = await app.inject({
    method: "GET", url: `/api/v1/audit-events/export?format=csv&projectId=${projectId}`, headers: headers(orgA, ownerA),
  });
  assert.equal(csv.statusCode, 200, csv.body);
  assert.equal(csv.json().data.format, "csv");
  assert.match(csv.json().data.content, /occurred_at/);
  assert.equal(csv.json().data.content.includes("postgres://"), false);
  const json = await app.inject({
    method: "GET", url: `/api/v1/audit-events/export?format=json&projectId=${projectId}`, headers: headers(orgA, ownerA),
  });
  assert.equal(json.statusCode, 200, json.body);
  assert.ok(JSON.parse(json.json().data.content).length >= 1);

  const settings = await app.inject({ method: "GET", url: "/api/v1/audit-settings", headers: headers(orgA, ownerA) });
  assert.equal(settings.statusCode, 200, settings.body);
  assert.equal(settings.json().data.retentionDays, 90);
  const updated = await app.inject({
    method: "PATCH", url: "/api/v1/audit-settings", headers: headers(orgA, ownerA), payload: { retentionDays: 365 },
  });
  assert.equal(updated.statusCode, 200, updated.body);
  assert.equal(updated.json().data.retentionDays, 365);
  const retentionAudit = await app.inject({
    method: "GET", url: "/api/v1/audit-events?action=organization.audit_retention_updated", headers: headers(orgA, ownerA),
  });
  assert.equal(retentionAudit.statusCode, 200, retentionAudit.body);
  assert.equal(retentionAudit.json().data.events.length, 1);

  const otherTenant = await app.inject({ method: "GET", url: "/api/v1/audit-events", headers: headers(orgB, ownerB) });
  assert.equal(otherTenant.statusCode, 200, otherTenant.body);
  assert.equal(otherTenant.body.includes(projectId), false);
});

test("previews and commits dotenv imports with explicit conflict strategies", async () => {
  const conflictedContent = [
    "CACHE_URL=redis://dotenv-update",
    "NEW_FROM_DOTENV=first-import-value",
    "BROKEN LINE",
  ].join("\n");
  const preview = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/imports/dotenv/preview`,
    headers: headers(orgA, memberA),
    payload: { content: conflictedContent },
  });
  assert.equal(preview.statusCode, 200, preview.body);
  assert.deepEqual(preview.json().data.summary, { adds: 1, updates: 1, conflicts: 1 });
  assert.deepEqual(preview.json().data.entries.map(({ key, operation }: { key: string; operation: string }) => ({ key, operation })), [
    { key: "CACHE_URL", operation: "update" },
    { key: "NEW_FROM_DOTENV", operation: "add" },
  ]);
  assert.equal(preview.body.includes("first-import-value"), false);

  const rejected = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/imports/dotenv`,
    headers: headers(orgA, memberA),
    payload: { content: conflictedContent, strategy: "overwrite" },
  });
  assert.equal(rejected.statusCode, 400, rejected.body);
  assert.equal(rejected.json().error.code, "DOTENV_PARSE_ERROR");

  const content = "CACHE_URL=redis://dotenv-update\nNEW_FROM_DOTENV=first-import-value";
  const skipped = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/imports/dotenv`,
    headers: headers(orgA, memberA),
    payload: { content, strategy: "skip" },
  });
  assert.equal(skipped.statusCode, 200, skipped.body);
  assert.deepEqual(skipped.json().data.summary, { requested: 2, created: 1, updated: 0, skipped: 1 });

  const merged = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/imports/dotenv`,
    headers: headers(orgA, memberA),
    payload: { content, strategy: "merge", selectedKeys: ["CACHE_URL"] },
  });
  assert.equal(merged.statusCode, 200, merged.body);
  assert.deepEqual(merged.json().data.summary, { requested: 2, created: 0, updated: 1, skipped: 1 });

  const values = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets/bulk-get`,
    headers: headers(orgA, memberA),
    payload: { keys: ["CACHE_URL", "NEW_FROM_DOTENV"] },
  });
  assert.equal(values.statusCode, 200, values.body);
  assert.deepEqual(values.json().data, {
    CACHE_URL: "redis://dotenv-update",
    NEW_FROM_DOTENV: "first-import-value",
  });

  const protectedPreview = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${productionId}/imports/dotenv/preview`,
    headers: headers(orgA, memberA),
    payload: { content: "PROTECTED_IMPORT=denied" },
  });
  assert.equal(protectedPreview.statusCode, 403, protectedPreview.body);
});

test("previews and commits flat or nested JSON with stable primitive conversion", async () => {
  const content = JSON.stringify({
    DATABASE: { HOST: "db.internal", PORT: 5432, TLS: true },
    CACHE_URL: "redis://json-update",
  });
  const preview = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/imports/json/preview`,
    headers: headers(orgA, memberA),
    payload: { content, delimiter: "__" },
  });
  assert.equal(preview.statusCode, 200, preview.body);
  assert.deepEqual(preview.json().data.summary, { adds: 3, updates: 1, conflicts: 0 });
  assert.deepEqual(preview.json().data.entries.map(({ key }: { key: string }) => key), [
    "DATABASE__HOST", "DATABASE__PORT", "DATABASE__TLS", "CACHE_URL",
  ]);
  assert.equal(preview.body.includes("db.internal"), false);
  assert.equal(preview.body.includes("redis://json-update"), false);

  const arrayPreview = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/imports/json/preview`,
    headers: headers(orgA, memberA),
    payload: { content: '{"DATABASE":{"HOSTS":["one","two"]}}' },
  });
  assert.equal(arrayPreview.statusCode, 200, arrayPreview.body);
  assert.equal(arrayPreview.json().data.conflicts[0].code, "ARRAY_NOT_SUPPORTED");
  assert.equal(arrayPreview.json().data.conflicts[0].path, "$.DATABASE.HOSTS");
  const rejected = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/imports/json`,
    headers: headers(orgA, memberA),
    payload: { content: '{"DATABASE":{"HOSTS":["one","two"]}}', strategy: "overwrite" },
  });
  assert.equal(rejected.statusCode, 400, rejected.body);
  assert.equal(rejected.json().error.code, "JSON_IMPORT_ERROR");

  const imported = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/imports/json`,
    headers: headers(orgA, memberA),
    payload: { content, delimiter: "__", strategy: "overwrite" },
  });
  assert.equal(imported.statusCode, 200, imported.body);
  assert.deepEqual(imported.json().data.summary, { requested: 4, created: 3, updated: 1, skipped: 0 });

  const values = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets/bulk-get`,
    headers: headers(orgA, memberA),
    payload: { keys: ["DATABASE__HOST", "DATABASE__PORT", "DATABASE__TLS", "CACHE_URL"] },
  });
  assert.equal(values.statusCode, 200, values.body);
  assert.deepEqual(values.json().data, {
    CACHE_URL: "redis://json-update",
    DATABASE__HOST: "db.internal",
    DATABASE__PORT: "5432",
    DATABASE__TLS: "true",
  });

  const customDelimiter = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/imports/json/preview`,
    headers: headers(orgA, memberA),
    payload: { content: '{"NESTED":{"KEY":"value"}}', delimiter: "." },
  });
  assert.equal(customDelimiter.statusCode, 200, customDelimiter.body);
  assert.equal(customDelimiter.json().data.entries[0].key, "NESTED.KEY");

  const auditRows = await database.withOrg(orgA, ownerA, (transaction) => transaction.query<{ metadata: Record<string, unknown> }>(
    "SELECT metadata FROM audit_events WHERE action = 'secret.imported' AND metadata->'details'->>'format' = 'json'",
  ));
  assert.equal(auditRows.rowCount, 1);
  assert.doesNotMatch(JSON.stringify(auditRows.rows), /db\.internal|redis:\/\/json-update/);
});

test("previews and promotes selected secrets while enforcing target protection", async () => {
  const denied = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${productionId}/promotions/preview`,
    headers: headers(orgA, memberA),
    payload: { sourceEnvironmentId: developmentId, keys: ["CACHE_URL", "DATABASE__HOST"] },
  });
  assert.equal(denied.statusCode, 403, denied.body);

  const preview = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${productionId}/promotions/preview`,
    headers: headers(orgA, ownerA),
    payload: { sourceEnvironmentId: developmentId, keys: ["CACHE_URL", "DATABASE__HOST"] },
  });
  assert.equal(preview.statusCode, 200, preview.body);
  assert.deepEqual(preview.json().data.summary, { selected: 2, created: 2, overwritten: 0 });
  assert.equal(preview.body.includes("redis://json-update"), false);
  assert.equal(preview.body.includes("db.internal"), false);

  const promoted = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${productionId}/promotions`,
    headers: headers(orgA, ownerA),
    payload: { sourceEnvironmentId: developmentId, keys: ["CACHE_URL", "DATABASE__HOST"] },
  });
  assert.equal(promoted.statusCode, 200, promoted.body);
  assert.deepEqual(promoted.json().data.summary, { selected: 2, created: 2, overwritten: 0 });
  assert.equal(promoted.json().data.secrets.length, 2);
  assert.equal(promoted.body.includes("redis://json-update"), false);

  const values = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${productionId}/secrets/bulk-get`,
    headers: headers(orgA, ownerA),
    payload: { keys: ["CACHE_URL", "DATABASE__HOST"] },
  });
  assert.equal(values.statusCode, 200, values.body);
  assert.deepEqual(values.json().data, { CACHE_URL: "redis://json-update", DATABASE__HOST: "db.internal" });

  const overwrite = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${productionId}/promotions/preview`,
    headers: headers(orgA, ownerA),
    payload: { sourceEnvironmentId: developmentId, keys: ["CACHE_URL"] },
  });
  assert.equal(overwrite.statusCode, 200, overwrite.body);
  assert.equal(overwrite.json().data.items[0].action, "overwrite");

  const auditRows = await database.withOrg(orgA, ownerA, (transaction) => transaction.query<{ metadata: Record<string, unknown> }>(
    "SELECT metadata FROM audit_events WHERE action = 'secret.promoted' ORDER BY id",
  ));
  assert.equal(auditRows.rowCount, 1);
  assert.doesNotMatch(JSON.stringify(auditRows.rows), /db\.internal|redis:\/\/json-update/);
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
  const wrongEnvironmentExport = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${productionId}/exports?format=json`,
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(wrongEnvironmentExport.statusCode, 403, wrongEnvironmentExport.body);
  assert.equal(wrongEnvironmentExport.json().error.code, "API_SCOPE_FORBIDDEN");

  const crossEnvironmentPromotion = await app.inject({
    method: "POST",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/promotions/preview`,
    headers: { authorization: `Bearer ${token}` },
    payload: { sourceEnvironmentId: productionId, keys: ["CACHE_URL"] },
  });
  assert.equal(crossEnvironmentPromotion.statusCode, 403, crossEnvironmentPromotion.body);
  assert.equal(crossEnvironmentPromotion.json().error.code, "API_SCOPE_FORBIDDEN");

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
  const readOnlyRuntime = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets/runtime`,
    headers: { authorization: `Bearer ${readOnlyToken}` },
  });
  assert.equal(readOnlyRuntime.statusCode, 200, readOnlyRuntime.body);
  assert.ok(readOnlyRuntime.headers.etag);
  const readOnlyExport = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/exports?format=shell`,
    headers: { authorization: `Bearer ${readOnlyToken}` },
  });
  assert.equal(readOnlyExport.statusCode, 200, readOnlyExport.body);
  assert.equal(readOnlyExport.json().data.format, "shell");
  const runtimeAudit = await database.withOrg(orgA, ownerA, (transaction) => transaction.query<{
    actor_type: string;
    actor_api_key_id: string;
    metadata: { details?: { count?: number; configVersion?: number } };
  }>(
    `SELECT actor_type, actor_api_key_id, metadata FROM audit_events
     WHERE action = 'secret.read' AND actor_api_key_id = $1 ORDER BY id DESC LIMIT 1`,
    [readOnlyCreated.json().data.apiKey.id],
  ));
  assert.equal(runtimeAudit.rows[0]?.actor_type, "api_key");
  assert.ok((runtimeAudit.rows[0]?.metadata.details?.count ?? 0) > 0);
  assert.ok(Number.isInteger(runtimeAudit.rows[0]?.metadata.details?.configVersion));
  const machineExportAudit = await database.withOrg(orgA, ownerA, (transaction) => transaction.query<{
    actor_api_key_id: string;
    metadata: { details?: { format?: string } };
  }>(
    `SELECT actor_api_key_id, metadata FROM audit_events
     WHERE action = 'secret.exported' AND actor_api_key_id = $1 ORDER BY id DESC LIMIT 1`,
    [readOnlyCreated.json().data.apiKey.id],
  ));
  assert.equal(machineExportAudit.rows[0]?.actor_api_key_id, readOnlyCreated.json().data.apiKey.id);
  assert.equal(machineExportAudit.rows[0]?.metadata.details?.format, "shell");
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
    database, tenancy, auth, apiKeys, audit, projects, environments, secrets, consistency,
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
  const projectWithoutDeletedTag = await app.inject({
    method: "GET", url: `/api/v1/projects/${projectId}`, headers: headers(orgA, ownerA),
  });
  assert.deepEqual(projectWithoutDeletedTag.json().data.tagIds, []);
  assert.deepEqual(projectWithoutDeletedTag.json().data.tags, []);
  const secretWithoutDeletedTag = await app.inject({
    method: "GET",
    url: `/api/v1/projects/${projectId}/environments/${developmentId}/secrets?search=TAGGED_CREDENTIAL`,
    headers: headers(orgA, ownerA),
  });
  assert.deepEqual(secretWithoutDeletedTag.json().data[0].tagIds, []);
  assert.deepEqual(secretWithoutDeletedTag.json().data[0].tags, []);
  const deletedProject = await app.inject({
    method: "DELETE", url: `/api/v1/projects/${projectId}`, headers: headers(orgA, ownerA),
  });
  assert.equal(deletedProject.statusCode, 200, deletedProject.body);
  assert.ok(deletedProject.json().data.deletedAt);
});
