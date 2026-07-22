import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { TransactionalAuditLog } from "@himitsu/audit";
import { AuthorizationContextResolver, AuthorizationError } from "@himitsu/authz";
import { TenantDatabase } from "@himitsu/tenancy";
import { Pool } from "pg";
import { ApiKeyError, ApiKeyService, tokenPrefix } from "../src/index.js";

const adminConnectionString = process.env.TEST_DATABASE_URL;
const appConnectionString = process.env.TEST_APP_DATABASE_URL;
if (adminConnectionString === undefined || appConnectionString === undefined) {
  throw new Error("TEST_DATABASE_URL and TEST_APP_DATABASE_URL are required");
}

const adminPool = new Pool({ connectionString: adminConnectionString, max: 2 });
const appPool = new Pool({ connectionString: appConnectionString, max: 8 });
const database = new TenantDatabase(appPool);
const orgA = randomUUID();
const orgB = randomUUID();
const ownerA = randomUUID();
const adminA = randomUUID();
const memberA = randomUUID();
const ownerB = randomUUID();
const projectA = randomUUID();
const projectB = randomUUID();
const apiKeys = new ApiKeyService(
  appPool,
  new AuthorizationContextResolver(),
  new TransactionalAuditLog(appPool),
);
let environmentA: string;
let organizationToken: string;
let organizationKeyId: string;
let projectToken: string;
let environmentToken: string;
let expiredToken: string;

before(async () => {
  await adminPool.query(
    `INSERT INTO users (id, email, email_verified_at) VALUES
      ($1, 'key-owner-a@example.com', now()), ($2, 'key-admin-a@example.com', now()),
      ($3, 'key-member-a@example.com', now()), ($4, 'key-owner-b@example.com', now())`,
    [ownerA, adminA, memberA, ownerB],
  );
  await adminPool.query(
    "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Key Alpha', 'key-alpha'), ($2, 'Key Beta', 'key-beta')",
    [orgA, orgB],
  );
  await adminPool.query(
    `INSERT INTO memberships (org_id, user_id, role) VALUES
      ($1, $2, 'owner'), ($1, $3, 'admin'), ($1, $4, 'member'), ($5, $6, 'owner')`,
    [orgA, ownerA, adminA, memberA, orgB, ownerB],
  );
  await database.withOrg(orgA, ownerA, async (transaction) => {
    await transaction.query(
      `INSERT INTO projects (id, org_id, name, slug, settings, created_by_user_id)
       VALUES ($1, $2, 'Key Project', 'key-project', '{"defaultEnvironments":["development"]}', $3)`,
      [projectA, orgA, ownerA],
    );
    environmentA = (await transaction.query<{ id: string }>(
      "SELECT id FROM environments WHERE project_id = $1",
      [projectA],
    )).rows[0]?.id ?? "";
    assert.ok(environmentA);
  });
  await database.withOrg(orgB, ownerB, (transaction) => transaction.query(
    `INSERT INTO projects (id, org_id, name, slug, settings, created_by_user_id)
     VALUES ($1, $2, 'Other Key Project', 'other-key-project', '{}', $3)`,
    [projectB, orgB, ownerB],
  ));
});

after(async () => {
  await appPool.end();
  await adminPool.end();
});

test("creates org, project, and environment-scoped credentials and reveals plaintext once", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const organization = await apiKeys.create(transaction, ownerA, {
      name: "Organization runtime",
      access: "read_only",
    });
    organizationToken = organization.token;
    organizationKeyId = organization.apiKey.id;
    assert.match(organization.token, /^himi_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
    assert.equal(organization.apiKey.projectId, null);
    assert.equal(organization.apiKey.environmentId, null);

    const project = await apiKeys.create(transaction, ownerA, {
      name: "Project CI",
      access: "read_write",
      projectId: projectA,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });
    projectToken = project.token;
    assert.equal(project.apiKey.projectId, projectA);
    assert.equal(project.apiKey.environmentId, null);

    const environment = await apiKeys.create(transaction, ownerA, {
      name: "Environment runtime",
      access: "read_only",
      projectId: projectA,
      environmentId: environmentA,
    });
    environmentToken = environment.token;
    assert.equal(environment.apiKey.environmentId, environmentA);

    const expiring = await apiKeys.create(transaction, ownerA, {
      name: "Expired soon",
      access: "read_only",
      projectId: projectA,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });
    expiredToken = expiring.token;

    const listed = await apiKeys.list(transaction, adminA);
    assert.equal(listed.length, 4);
    assert.equal(JSON.stringify(listed).includes(organizationToken), false);
    assert.equal(JSON.stringify(listed).includes(projectToken), false);
    const stored = await transaction.query<{ prefix: string; hash_length: number; hash_hex: string }>(
      `SELECT prefix, octet_length(token_hash) AS hash_length, encode(token_hash, 'hex') AS hash_hex
       FROM api_keys WHERE id = $1`,
      [organizationKeyId],
    );
    assert.equal(stored.rows[0]?.prefix, organization.apiKey.prefix);
    assert.equal(stored.rows[0]?.hash_length, 32);
    assert.notEqual(stored.rows[0]?.hash_hex, organizationToken);
  });
});

test("enforces management permissions, active scope, and project downgrades", async () => {
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) => apiKeys.create(transaction, memberA, {
      name: "Denied",
      access: "read_only",
    })),
    (error: unknown) => error instanceof AuthorizationError,
  );
  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) => apiKeys.create(transaction, ownerA, {
      name: "Missing project",
      access: "read_only",
      projectId: randomUUID(),
    })),
    (error: unknown) => error instanceof ApiKeyError && error.code === "NOT_FOUND",
  );
  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) => apiKeys.create(transaction, ownerA, {
      name: "Environment without project",
      access: "read_only",
      environmentId: environmentA,
    })),
    (error: unknown) => error instanceof ApiKeyError && error.code === "INVALID_INPUT",
  );
  await database.withOrg(orgA, ownerA, (transaction) => transaction.query(
    `INSERT INTO project_role_overrides
      (org_id, project_id, user_id, role, created_by_user_id)
     VALUES ($1, $2, $3, 'read_only', $4)`,
    [orgA, projectA, adminA, ownerA],
  ));
  await assert.rejects(
    database.withOrg(orgA, adminA, (transaction) => apiKeys.create(transaction, adminA, {
      name: "Downgraded",
      access: "read_write",
      projectId: projectA,
    })),
    (error: unknown) => error instanceof AuthorizationError,
  );
});

test("authenticates exact tokens, tracks use, and audits without credential material", async () => {
  const before = new Date();
  const principal = await apiKeys.authenticate(organizationToken, {
    ip: "192.0.2.10",
    userAgent: "himitsu-integration/1",
  });
  assert.equal(principal.apiKeyId, organizationKeyId);
  assert.equal(principal.orgId, orgA);
  assert.equal(principal.access, "read_only");
  assert.ok(principal.usedAt.getTime() >= before.getTime());
  const projectPrincipal = await apiKeys.authenticate(projectToken);
  assert.equal(projectPrincipal.projectId, projectA);
  assert.equal(projectPrincipal.environmentId, null);
  assert.equal(projectPrincipal.access, "read_write");
  const environmentPrincipal = await apiKeys.authenticate(environmentToken);
  assert.equal(environmentPrincipal.projectId, projectA);
  assert.equal(environmentPrincipal.environmentId, environmentA);

  await assert.rejects(
    apiKeys.authenticate(`${organizationToken.slice(0, -1)}${organizationToken.endsWith("A") ? "B" : "A"}`),
    (error: unknown) => error instanceof ApiKeyError && error.code === "INVALID_TOKEN",
  );
  const event = await database.withOrg(orgA, ownerA, (transaction) => transaction.query<{
    actor_api_key_id: string;
    ip: string;
    user_agent: string;
    metadata: Record<string, unknown>;
  }>(
    `SELECT actor_api_key_id, host(ip) AS ip, user_agent, metadata
     FROM audit_events WHERE action = 'api_key.used' AND actor_api_key_id = $1`,
    [organizationKeyId],
  ));
  assert.equal(event.rows[0]?.actor_api_key_id, organizationKeyId);
  assert.equal(event.rows[0]?.ip, "192.0.2.10");
  assert.equal(event.rows[0]?.user_agent, "himitsu-integration/1");
  const encoded = JSON.stringify(event.rows[0]?.metadata);
  assert.equal(encoded.includes(organizationToken), false);
  assert.doesNotMatch(encoded, /token|credential|hash/i);
});

test("rejects expired and revoked tokens without advancing last-used state", async () => {
  const expiredPrefix = tokenPrefix(expiredToken);
  await adminPool.query(
    `UPDATE api_keys
     SET created_at = now() - interval '2 seconds', expires_at = now() - interval '1 second'
     WHERE prefix = $1`,
    [expiredPrefix],
  );
  await assert.rejects(
    apiKeys.authenticate(expiredToken),
    (error: unknown) => error instanceof ApiKeyError && error.code === "INVALID_TOKEN",
  );
  assert.equal((await adminPool.query<{ last_used_at: Date | null }>(
    "SELECT last_used_at FROM api_keys WHERE prefix = $1",
    [expiredPrefix],
  )).rows[0]?.last_used_at, null);
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const revoked = await apiKeys.revoke(transaction, ownerA, organizationKeyId);
    assert.ok(revoked.revokedAt instanceof Date);
    assert.equal((await apiKeys.revoke(transaction, ownerA, organizationKeyId)).revokedAt?.getTime(), revoked.revokedAt?.getTime());
  });
  await assert.rejects(
    apiKeys.authenticate(organizationToken),
    (error: unknown) => error instanceof ApiKeyError && error.code === "INVALID_TOKEN",
  );
});

test("forced RLS keeps API key registries tenant-local", async () => {
  let otherTenantToken = "";
  await database.withOrg(orgB, ownerB, async (transaction) => {
    otherTenantToken = (await apiKeys.create(transaction, ownerB, {
      name: "Other tenant",
      access: "read_only",
      projectId: projectB,
    })).token;
    assert.equal((await apiKeys.list(transaction, ownerB)).length, 1);
  });
  await database.withOrg(orgA, ownerA, async (transaction) => {
    assert.equal((await apiKeys.list(transaction, ownerA)).length, 4);
    const actions = await transaction.query<{ action: string }>(
      "SELECT action FROM audit_events WHERE action IN ('api_key.created', 'api_key.revoked') ORDER BY id",
    );
    assert.deepEqual(actions.rows.map(({ action }) => action), [
      "api_key.created", "api_key.created", "api_key.created", "api_key.created", "api_key.revoked",
    ]);
  });
  await adminPool.query("UPDATE projects SET deleted_at = now() WHERE id = $1", [projectB]);
  await assert.rejects(
    apiKeys.authenticate(otherTenantToken),
    (error: unknown) => error instanceof ApiKeyError && error.code === "INVALID_TOKEN",
  );
});
