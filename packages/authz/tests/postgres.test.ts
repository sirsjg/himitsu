import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { TransactionalAuditLog } from "@himitsu/audit";
import { TenantDatabase } from "@himitsu/tenancy";
import { Pool } from "pg";
import {
  AuthorizationContextResolver,
  AuthorizationError,
  ProjectRoleOverrideService,
  authorize,
} from "../src/index.js";

const adminConnectionString = process.env.TEST_DATABASE_URL;
const appConnectionString = process.env.TEST_APP_DATABASE_URL;
if (adminConnectionString === undefined || appConnectionString === undefined) {
  throw new Error("TEST_DATABASE_URL and TEST_APP_DATABASE_URL are required");
}

const adminPool = new Pool({ connectionString: adminConnectionString, max: 2 });
const appPool = new Pool({ connectionString: appConnectionString, max: 5 });
const database = new TenantDatabase(appPool);
const resolver = new AuthorizationContextResolver();
const overrides = new ProjectRoleOverrideService(resolver, new TransactionalAuditLog(appPool));
const orgA = randomUUID();
const orgB = randomUUID();
const ownerA = randomUUID();
const memberA = randomUUID();
const ownerB = randomUUID();
const projectA = randomUUID();
const projectB = randomUUID();

before(async () => {
  await adminPool.query(
    "INSERT INTO users (id, email, email_verified_at) VALUES ($1, 'owner-a@example.com', now()), ($2, 'member-a@example.com', now()), ($3, 'owner-b@example.com', now())",
    [ownerA, memberA, ownerB],
  );
  await adminPool.query(
    "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Alpha', 'alpha'), ($2, 'Beta', 'beta')",
    [orgA, orgB],
  );
  await adminPool.query(
    `INSERT INTO memberships (org_id, user_id, role) VALUES
      ($1, $2, 'owner'), ($1, $3, 'member'), ($4, $5, 'owner')`,
    [orgA, ownerA, memberA, orgB, ownerB],
  );
  await adminPool.query(
    "INSERT INTO projects (id, org_id, name, slug) VALUES ($1, $2, 'Alpha API', 'api'), ($3, $4, 'Beta API', 'api')",
    [projectA, orgA, projectB, orgB],
  );
});

after(async () => {
  await appPool.end();
  await adminPool.end();
});

test("resolves base roles and persists audited project downgrades", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const base = await resolver.resolve(transaction, memberA, projectA);
    assert.deepEqual(base, { orgRole: "member", projectRole: null, protectedEnvironment: false });
    assert.equal(authorize(base, "secret.write").allowed, true);

    await overrides.setOverride(transaction, ownerA, projectA, memberA, "read_only");
    const downgraded = await resolver.resolve(transaction, memberA, projectA);
    assert.deepEqual(downgraded, {
      orgRole: "member",
      projectRole: "read_only",
      protectedEnvironment: false,
    });
    assert.equal(authorize(downgraded, "secret.write").allowed, false);
    assert.equal(authorize(downgraded, "secret.read").allowed, true);
  });

  const evidence = await database.withOrg(orgA, ownerA, (transaction) =>
    transaction.query<{ action: string; metadata: { after: { role: string; targetUserId: string } } }>(
      "SELECT action, metadata FROM audit_events WHERE action = 'membership.project_role_changed'",
    ),
  );
  assert.equal(evidence.rows.length, 1);
  assert.equal(evidence.rows[0]?.metadata.after.role, "read_only");
  assert.equal(evidence.rows[0]?.metadata.after.targetUserId, memberA);
});

test("prevents project overrides from escalating and blocks non-admin management", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    await overrides.setOverride(transaction, ownerA, projectA, memberA, "admin");
    const context = await resolver.resolve(transaction, memberA, projectA);
    assert.equal(context.projectRole, "admin");
    assert.equal(authorize(context, "audit.read").allowed, false);
    assert.equal(authorize(context, "project.delete").allowed, false);
  });

  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      overrides.setOverride(transaction, memberA, projectA, memberA, "read_only"),
    ),
    (error: unknown) => error instanceof AuthorizationError && error.code === "FORBIDDEN",
  );
});

test("removes an override and restores the organization role", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    await overrides.removeOverride(transaction, ownerA, projectA, memberA);
    const context = await resolver.resolve(transaction, memberA, projectA);
    assert.equal(context.projectRole, null);
    assert.equal(authorize(context, "secret.write").allowed, true);
  });
});

test("RLS hides overrides outside the active organization", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    await overrides.setOverride(transaction, ownerA, projectA, memberA, "read_only");
    const visible = await transaction.query<{ project_id: string }>("SELECT project_id FROM project_role_overrides");
    assert.deepEqual(visible.rows.map(({ project_id }) => project_id), [projectA]);
  });
  const unscoped = await appPool.query("SELECT * FROM project_role_overrides");
  assert.equal(unscoped.rowCount, 0);
  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) =>
      transaction.query(
        "INSERT INTO project_role_overrides (org_id, project_id, user_id, role, created_by_user_id) VALUES ($1, $2, $3, 'read_only', $4)",
        [orgB, projectB, memberA, ownerA],
      ),
    ),
    (error: unknown) => ["42501", "23503"].includes((error as { code?: string }).code ?? ""),
  );
});
