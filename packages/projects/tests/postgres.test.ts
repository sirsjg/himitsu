import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { TransactionalAuditLog } from "@himitsu/audit";
import { AuthorizationContextResolver, AuthorizationError } from "@himitsu/authz";
import { TenantDatabase } from "@himitsu/tenancy";
import { Pool } from "pg";
import { ProjectError, ProjectService } from "../src/index.js";

const adminConnectionString = process.env.TEST_DATABASE_URL;
const appConnectionString = process.env.TEST_APP_DATABASE_URL;
if (adminConnectionString === undefined || appConnectionString === undefined) {
  throw new Error("TEST_DATABASE_URL and TEST_APP_DATABASE_URL are required");
}

const adminPool = new Pool({ connectionString: adminConnectionString, max: 2 });
const appPool = new Pool({ connectionString: appConnectionString, max: 6 });
const database = new TenantDatabase(appPool);
const orgA = randomUUID();
const orgB = randomUUID();
const ownerA = randomUUID();
const memberA = randomUUID();
const readerA = randomUUID();
const ownerB = randomUUID();
const tagA = randomUUID();
const tagASecond = randomUUID();
let now = new Date("2026-07-22T00:00:00.000Z");
const projects = new ProjectService(
  new AuthorizationContextResolver(),
  new TransactionalAuditLog(appPool),
  { now: () => new Date(now), recoveryDays: 30 },
);
let projectId: string;

before(async () => {
  await adminPool.query(
    `INSERT INTO users (id, email, email_verified_at) VALUES
      ($1, 'owner-a@example.com', now()), ($2, 'member-a@example.com', now()),
      ($3, 'reader-a@example.com', now()), ($4, 'owner-b@example.com', now())`,
    [ownerA, memberA, readerA, ownerB],
  );
  await adminPool.query(
    "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Alpha', 'alpha'), ($2, 'Beta', 'beta')",
    [orgA, orgB],
  );
  await adminPool.query(
    `INSERT INTO memberships (org_id, user_id, role) VALUES
      ($1, $2, 'owner'), ($1, $3, 'member'), ($1, $4, 'read_only'), ($5, $6, 'owner')`,
    [orgA, ownerA, memberA, readerA, orgB, ownerB],
  );
  await adminPool.query(
    "INSERT INTO tags (id, org_id, name, color) VALUES ($1, $2, 'backend', '#112233'), ($3, $2, 'critical', '#445566')",
    [tagA, orgA, tagASecond],
  );
});

after(async () => {
  await appPool.end();
  await adminPool.end();
});

test("creates, addresses, lists, and updates project settings and tags", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const created = await projects.create(transaction, ownerA, {
      name: "Customer API",
      slug: "customer-api",
      description: "Primary customer service",
      defaultEnvironments: ["dev", "prod"],
      tagIds: [tagA],
    });
    projectId = created.id;
    assert.equal(created.orgId, orgA);
    assert.deepEqual(created.settings.defaultEnvironments, ["dev", "prod"]);
    assert.deepEqual(created.tagIds, [tagA]);
    assert.equal((await projects.getBySlug(transaction, ownerA, "customer-api")).id, projectId);
    assert.equal((await projects.list(transaction, ownerA)).length, 1);

    const updated = await projects.update(transaction, memberA, projectId, {
      name: "Customer Platform API",
      slug: "customer-platform",
      description: "Renamed service",
      defaultEnvironments: ["development", "staging", "production"],
      tagIds: [tagASecond, tagA],
    });
    assert.equal(updated.name, "Customer Platform API");
    assert.equal(updated.slug, "customer-platform");
    assert.equal(updated.description, "Renamed service");
    assert.deepEqual(new Set(updated.tagIds), new Set([tagA, tagASecond]));
  });

  await database.withOrg(orgB, ownerB, async (transaction) => {
    const sameSlug = await projects.create(transaction, ownerB, {
      name: "Same Slug Other Org",
      slug: "customer-platform",
    });
    assert.equal(sameSlug.orgId, orgB);
  });
});

test("enforces project permissions and slug/tag constraints", async () => {
  await assert.rejects(
    database.withOrg(orgA, readerA, (transaction) =>
      projects.create(transaction, readerA, { name: "Denied", slug: "denied" }),
    ),
    (error: unknown) => error instanceof AuthorizationError,
  );
  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) =>
      projects.create(transaction, ownerA, { name: "Duplicate", slug: "customer-platform" }),
    ),
    (error: unknown) => error instanceof ProjectError && error.code === "SLUG_EXISTS",
  );
  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) =>
      projects.update(transaction, ownerA, projectId, { tagIds: [randomUUID()] }),
    ),
    (error: unknown) => error instanceof ProjectError && error.code === "TAG_NOT_FOUND",
  );
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      projects.setArchived(transaction, memberA, projectId, true),
    ),
    (error: unknown) => error instanceof AuthorizationError,
  );
  await database.withOrg(orgA, ownerA, async (transaction) => {
    assert.ok((await projects.setArchived(transaction, ownerA, projectId, true)).archivedAt instanceof Date);
    assert.equal((await projects.setArchived(transaction, ownerA, projectId, false)).archivedAt, null);
  });
});

test("soft-deletes children and restores only rows deleted by the project cascade", async () => {
  const activeEnvironment = randomUUID();
  const independentlyDeletedEnvironment = randomUUID();
  const activeSecret = randomUUID();
  await database.withOrg(orgA, ownerA, async (transaction) => {
    await transaction.query(
      `INSERT INTO environments (id, org_id, project_id, name, slug) VALUES
        ($1, $2, $3, 'Active', 'active'), ($4, $2, $3, 'Old', 'old')`,
      [activeEnvironment, orgA, projectId, independentlyDeletedEnvironment],
    );
    await transaction.query(
      "UPDATE environments SET deleted_at = now() - interval '1 day' WHERE id = $1",
      [independentlyDeletedEnvironment],
    );
    await transaction.query(
      "INSERT INTO secrets (id, org_id, project_id, environment_id, key) VALUES ($1, $2, $3, $4, 'DATABASE_URL')",
      [activeSecret, orgA, projectId, activeEnvironment],
    );

    const deleted = await projects.delete(transaction, ownerA, projectId);
    assert.equal(deleted.deletedAt?.toISOString(), "2026-07-22T00:00:00.000Z");
    assert.equal(deleted.purgeAfter?.toISOString(), "2026-08-21T00:00:00.000Z");
    await assert.rejects(
      projects.getBySlug(transaction, ownerA, "customer-platform"),
      (error: unknown) => error instanceof ProjectError && error.code === "NOT_FOUND",
    );
    const children = await transaction.query<{
      id: string;
      deleted_at: Date | null;
      deleted_by_project_at: Date | null;
    }>("SELECT id, deleted_at, deleted_by_project_at FROM environments ORDER BY id");
    const active = children.rows.find(({ id }) => id === activeEnvironment);
    const old = children.rows.find(({ id }) => id === independentlyDeletedEnvironment);
    assert.ok(active?.deleted_by_project_at instanceof Date);
    assert.equal(old?.deleted_by_project_at, null);

    const restored = await projects.restore(transaction, ownerA, projectId);
    assert.equal(restored.deletedAt, null);
    const restoredChildren = await transaction.query<{
      id: string;
      deleted_at: Date | null;
    }>("SELECT id, deleted_at FROM environments ORDER BY id");
    assert.equal(restoredChildren.rows.find(({ id }) => id === activeEnvironment)?.deleted_at, null);
    assert.ok(restoredChildren.rows.find(({ id }) => id === independentlyDeletedEnvironment)?.deleted_at instanceof Date);
    const secret = await transaction.query<{ deleted_at: Date | null; deleted_by_project_at: Date | null }>(
      "SELECT deleted_at, deleted_by_project_at FROM secrets WHERE id = $1",
      [activeSecret],
    );
    assert.equal(secret.rows[0]?.deleted_at, null);
    assert.equal(secret.rows[0]?.deleted_by_project_at, null);
  });
});

test("rejects restoration after the recovery window", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    await projects.delete(transaction, ownerA, projectId);
  });
  now = new Date("2026-08-22T00:00:00.000Z");
  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) => projects.restore(transaction, ownerA, projectId)),
    (error: unknown) => error instanceof ProjectError && error.code === "RECOVERY_EXPIRED",
  );
});

test("records project lifecycle audit events without secret data", async () => {
  const events = await database.withOrg(orgA, ownerA, (transaction) =>
    transaction.query<{ action: string }>(
      "SELECT action FROM audit_events WHERE resource_type = 'project' ORDER BY id",
    ),
  );
  assert.deepEqual(events.rows.map(({ action }) => action), [
    "project.created",
    "project.updated",
    "project.archived",
    "project.archived",
    "project.deleted",
    "project.restored",
    "project.deleted",
  ]);
});
