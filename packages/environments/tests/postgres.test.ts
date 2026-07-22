import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { TransactionalAuditLog } from "@himitsu/audit";
import { AuthorizationContextResolver, AuthorizationError } from "@himitsu/authz";
import { TenantDatabase } from "@himitsu/tenancy";
import { Pool } from "pg";
import { EnvironmentError, EnvironmentService } from "../src/index.js";

const adminConnectionString = process.env.TEST_DATABASE_URL;
const appConnectionString = process.env.TEST_APP_DATABASE_URL;
if (adminConnectionString === undefined || appConnectionString === undefined) {
  throw new Error("TEST_DATABASE_URL and TEST_APP_DATABASE_URL are required");
}

const adminPool = new Pool({ connectionString: adminConnectionString, max: 2 });
const appPool = new Pool({ connectionString: appConnectionString, max: 6 });
const database = new TenantDatabase(appPool);
const resolver = new AuthorizationContextResolver();
const orgA = randomUUID();
const orgB = randomUUID();
const ownerA = randomUUID();
const memberA = randomUUID();
const readerA = randomUUID();
const ownerB = randomUUID();
const projectA = randomUUID();
const singleEnvironmentProject = randomUUID();
const projectB = randomUUID();
let now = new Date("2026-07-22T00:00:00.000Z");
const environments = new EnvironmentService(
  resolver,
  new TransactionalAuditLog(appPool),
  { now: () => new Date(now), recoveryDays: 30 },
);
let customEnvironmentId: string;

before(async () => {
  await adminPool.query(
    `INSERT INTO users (id, email, email_verified_at) VALUES
      ($1, 'env-owner-a@example.com', now()), ($2, 'env-member-a@example.com', now()),
      ($3, 'env-reader-a@example.com', now()), ($4, 'env-owner-b@example.com', now())`,
    [ownerA, memberA, readerA, ownerB],
  );
  await adminPool.query(
    "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Env Alpha', 'env-alpha'), ($2, 'Env Beta', 'env-beta')",
    [orgA, orgB],
  );
  await adminPool.query(
    `INSERT INTO memberships (org_id, user_id, role) VALUES
      ($1, $2, 'owner'), ($1, $3, 'member'), ($1, $4, 'read_only'), ($5, $6, 'owner')`,
    [orgA, ownerA, memberA, readerA, orgB, ownerB],
  );
  await database.withOrg(orgA, ownerA, async (transaction) => {
    await transaction.query(
      `INSERT INTO projects (id, org_id, name, slug, settings, created_by_user_id) VALUES
        ($1, $2, 'Environment Project', 'environment-project',
         '{"defaultEnvironments":["development","staging","production"]}', $3),
        ($4, $2, 'Single Environment', 'single-environment',
         '{"defaultEnvironments":["only"]}', $3)`,
      [projectA, orgA, ownerA, singleEnvironmentProject],
    );
  });
  await database.withOrg(orgB, ownerB, async (transaction) => {
    await transaction.query(
      `INSERT INTO projects (id, org_id, name, slug, settings, created_by_user_id)
       VALUES ($1, $2, 'Other Tenant', 'other-tenant', '{}', $3)`,
      [projectB, orgB, ownerB],
    );
  });
});

after(async () => {
  await appPool.end();
  await adminPool.end();
});

test("creates ordered defaults and supports custom environments", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const defaults = await environments.list(transaction, ownerA, projectA);
    assert.deepEqual(defaults.map(({ slug }) => slug), ["development", "staging", "production"]);
    assert.deepEqual(defaults.map(({ displayOrder }) => displayOrder), [0, 1, 2]);
    assert.deepEqual(defaults.map(({ protected: isProtected }) => isProtected), [false, false, true]);
  });

  await database.withOrg(orgA, memberA, async (transaction) => {
    const custom = await environments.create(transaction, memberA, projectA, {
      name: "Preview",
      slug: "preview",
    });
    customEnvironmentId = custom.id;
    assert.equal(custom.displayOrder, 3);
    const renamed = await environments.update(transaction, memberA, custom.id, {
      name: "Quality Assurance",
      slug: "qa",
    });
    assert.equal(renamed.slug, "qa");
  });

  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      environments.create(transaction, memberA, projectA, {
        name: "Protected Preview",
        slug: "protected-preview",
        protected: true,
      }),
    ),
    (error: unknown) => error instanceof AuthorizationError
      && error.decision.reason === "protected_environment",
  );

  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) =>
      environments.create(transaction, ownerA, projectA, { name: "Duplicate", slug: "qa" }),
    ),
    (error: unknown) => error instanceof EnvironmentError && error.code === "SLUG_EXISTS",
  );
});

test("enforces protection, project overrides, and complete atomic ordering", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const protectedCustom = await environments.update(transaction, ownerA, customEnvironmentId, {
      protected: true,
    });
    assert.equal(protectedCustom.protected, true);
  });
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      environments.update(transaction, memberA, customEnvironmentId, { name: "Denied" }),
    ),
    (error: unknown) => error instanceof AuthorizationError
      && error.decision.reason === "protected_environment",
  );
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const current = await environments.list(transaction, ownerA, projectA);
    await assert.rejects(
      environments.reorder(transaction, ownerA, projectA, current.slice(1).map(({ id }) => id)),
      (error: unknown) => error instanceof EnvironmentError && error.code === "ORDER_MISMATCH",
    );
    const reversedIds = current.map(({ id }) => id).reverse();
    const reordered = await environments.reorder(transaction, ownerA, projectA, reversedIds);
    assert.deepEqual(reordered.map(({ id }) => id), reversedIds);
    assert.deepEqual(reordered.map(({ displayOrder }) => displayOrder), [0, 1, 2, 3]);
    await transaction.query(
      `INSERT INTO project_role_overrides
        (org_id, project_id, user_id, role, created_by_user_id)
       VALUES ($1, $2, $3, 'read_only', $4)`,
      [orgA, projectA, memberA, ownerA],
    );
  });
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      environments.create(transaction, memberA, projectA, { name: "Denied", slug: "denied" }),
    ),
    (error: unknown) => error instanceof AuthorizationError && error.decision.reason === "role",
  );
  await database.withOrg(orgA, ownerA, (transaction) =>
    transaction.query(
      "DELETE FROM project_role_overrides WHERE project_id = $1 AND user_id = $2",
      [projectA, memberA],
    ),
  );
});

test("requires secret confirmation and selectively restores environment cascades", async () => {
  const cascadedSecret = randomUUID();
  const independentlyDeletedSecret = randomUUID();
  await database.withOrg(orgA, ownerA, async (transaction) => {
    await transaction.query(
      `INSERT INTO secrets (id, org_id, project_id, environment_id, key) VALUES
        ($1, $2, $3, $4, 'ACTIVE_SECRET'), ($5, $2, $3, $4, 'OLD_SECRET')`,
      [cascadedSecret, orgA, projectA, customEnvironmentId, independentlyDeletedSecret],
    );
    await transaction.query(
      "UPDATE secrets SET deleted_at = now() - interval '1 day' WHERE id = $1",
      [independentlyDeletedSecret],
    );
    await assert.rejects(
      environments.delete(transaction, ownerA, customEnvironmentId),
      (error: unknown) => error instanceof EnvironmentError
        && error.code === "SECRETS_REQUIRE_CONFIRMATION",
    );
    const deleted = await environments.delete(transaction, ownerA, customEnvironmentId, {
      confirmSecrets: true,
    });
    assert.equal(deleted.deletedAt?.toISOString(), "2026-07-22T00:00:00.000Z");
    assert.equal(deleted.purgeAfter?.toISOString(), "2026-08-21T00:00:00.000Z");
    const deletedSecrets = await transaction.query<{
      id: string;
      deleted_at: Date | null;
      deleted_by_environment_at: Date | null;
    }>(
      "SELECT id, deleted_at, deleted_by_environment_at FROM secrets WHERE environment_id = $1 ORDER BY id",
      [customEnvironmentId],
    );
    assert.ok(deletedSecrets.rows.find(({ id }) => id === cascadedSecret)?.deleted_by_environment_at instanceof Date);
    assert.equal(
      deletedSecrets.rows.find(({ id }) => id === independentlyDeletedSecret)?.deleted_by_environment_at,
      null,
    );
    await environments.restore(transaction, ownerA, customEnvironmentId);
    const restoredSecrets = await transaction.query<{
      id: string;
      deleted_at: Date | null;
    }>("SELECT id, deleted_at FROM secrets WHERE environment_id = $1 ORDER BY id", [customEnvironmentId]);
    assert.equal(restoredSecrets.rows.find(({ id }) => id === cascadedSecret)?.deleted_at, null);
    assert.ok(restoredSecrets.rows.find(({ id }) => id === independentlyDeletedSecret)?.deleted_at instanceof Date);
  });
});

test("prevents deleting a project's last environment and rejects expired recovery", async () => {
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const only = (await environments.list(transaction, ownerA, singleEnvironmentProject))[0];
    assert.ok(only);
    await assert.rejects(
      environments.delete(transaction, ownerA, only.id),
      (error: unknown) => error instanceof EnvironmentError && error.code === "LAST_ENVIRONMENT",
    );
    const expiring = await environments.create(transaction, ownerA, projectA, {
      name: "Temporary",
      slug: "temporary",
    });
    await environments.delete(transaction, ownerA, expiring.id);
    now = new Date("2026-08-22T00:00:00.000Z");
    await assert.rejects(
      environments.restore(transaction, ownerA, expiring.id),
      (error: unknown) => error instanceof EnvironmentError && error.code === "RECOVERY_EXPIRED",
    );
  });
});

test("forced RLS hides environments in another organization", async () => {
  const otherTenantEnvironment = await database.withOrg(orgB, ownerB, async (transaction) => {
    const rows = await environments.list(transaction, ownerB, projectB);
    assert.equal(rows.length, 3);
    return rows[0]?.id;
  });
  assert.ok(otherTenantEnvironment);
  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) =>
      environments.update(transaction, ownerA, otherTenantEnvironment, { name: "Cross tenant" }),
    ),
    (error: unknown) => error instanceof EnvironmentError && error.code === "NOT_FOUND",
  );
});

test("records each successful environment lifecycle action", async () => {
  const actions = await database.withOrg(orgA, ownerA, (transaction) =>
    transaction.query<{ action: string }>(
      "SELECT action FROM audit_events WHERE action LIKE 'environment.%' ORDER BY id",
    ),
  );
  assert.deepEqual(actions.rows.map(({ action }) => action), [
    "environment.created",
    "environment.updated",
    "environment.updated",
    "environment.reordered",
    "environment.deleted",
    "environment.restored",
    "environment.created",
    "environment.deleted",
  ]);
});
