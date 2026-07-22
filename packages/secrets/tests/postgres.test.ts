import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { TransactionalAuditLog } from "@himitsu/audit";
import { AuthorizationContextResolver, AuthorizationError } from "@himitsu/authz";
import { LocalMasterKey } from "@himitsu/crypto";
import { TenantDatabase } from "@himitsu/tenancy";
import { Pool } from "pg";
import { SecretError, SecretService } from "../src/index.js";

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
const memberA = randomUUID();
const readerA = randomUUID();
const ownerB = randomUUID();
const projectA = randomUUID();
const projectB = randomUUID();
const secrets = new SecretService(
  new AuthorizationContextResolver(),
  new TransactionalAuditLog(appPool),
  new LocalMasterKey("secrets-integration-v1", Buffer.alloc(32, 7)),
);
let developmentEnvironmentId: string;
let productionEnvironmentId: string;
let databaseSecretId: string;

before(async () => {
  await adminPool.query(
    `INSERT INTO users (id, email, email_verified_at) VALUES
      ($1, 'secret-owner-a@example.com', now()), ($2, 'secret-member-a@example.com', now()),
      ($3, 'secret-reader-a@example.com', now()), ($4, 'secret-owner-b@example.com', now())`,
    [ownerA, memberA, readerA, ownerB],
  );
  await adminPool.query(
    "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Secret Alpha', 'secret-alpha'), ($2, 'Secret Beta', 'secret-beta')",
    [orgA, orgB],
  );
  await adminPool.query(
    `INSERT INTO memberships (org_id, user_id, role) VALUES
      ($1, $2, 'owner'), ($1, $3, 'member'), ($1, $4, 'read_only'), ($5, $6, 'owner')`,
    [orgA, ownerA, memberA, readerA, orgB, ownerB],
  );
  await database.withOrg(orgA, ownerA, async (transaction) => {
    await transaction.query(
      `INSERT INTO projects (id, org_id, name, slug, settings, created_by_user_id)
       VALUES ($1, $2, 'Secret Project', 'secret-project',
         '{"defaultEnvironments":["development","production"]}', $3)`,
      [projectA, orgA, ownerA],
    );
    const rows = await transaction.query<{ id: string; slug: string }>(
      "SELECT id, slug FROM environments WHERE project_id = $1 ORDER BY display_order",
      [projectA],
    );
    developmentEnvironmentId = rows.rows.find(({ slug }) => slug === "development")?.id ?? "";
    productionEnvironmentId = rows.rows.find(({ slug }) => slug === "production")?.id ?? "";
    assert.ok(developmentEnvironmentId);
    assert.ok(productionEnvironmentId);
  });
  await database.withOrg(orgB, ownerB, async (transaction) => {
    await transaction.query(
      `INSERT INTO projects (id, org_id, name, slug, settings, created_by_user_id)
       VALUES ($1, $2, 'Other Secret Project', 'other-secret-project', '{}', $3)`,
      [projectB, orgB, ownerB],
    );
  });
});

after(async () => {
  await appPool.end();
  await adminPool.end();
});

test("creates encrypted secrets and decrypts only on audited reads", async () => {
  const value = "postgres://app:correct-horse@example/database";
  await database.withOrg(orgA, memberA, async (transaction) => {
    const created = await secrets.create(
      transaction,
      memberA,
      projectA,
      developmentEnvironmentId,
      { key: "DATABASE_URL", value, notes: "Primary connection" },
    );
    databaseSecretId = created.id;
    assert.equal(created.currentVersion, 1);
    assert.equal(created.notes, "Primary connection");
  });

  await database.withOrg(orgA, readerA, async (transaction) => {
    const read = await secrets.get(transaction, readerA, databaseSecretId);
    assert.equal(read.value, value);
    assert.equal((await secrets.list(transaction, readerA, projectA, developmentEnvironmentId)).length, 1);
    const persisted = await transaction.query<{
      ciphertext: Buffer;
      nonce_length: number;
      tag_length: number;
      encryption_key_version: number;
    }>(
      `SELECT value_ciphertext AS ciphertext, octet_length(nonce) AS nonce_length,
              octet_length(auth_tag) AS tag_length, encryption_key_version
       FROM secret_versions WHERE secret_id = $1 AND version = 1`,
      [databaseSecretId],
    );
    assert.notEqual(persisted.rows[0]?.ciphertext.toString("utf8"), value);
    assert.equal(persisted.rows[0]?.nonce_length, 12);
    assert.equal(persisted.rows[0]?.tag_length, 16);
    assert.equal(persisted.rows[0]?.encryption_key_version, 1);
  });
});

test("updates values immutably and enforces key, value, and uniqueness validation", async () => {
  await database.withOrg(orgA, memberA, async (transaction) => {
    const updated = await secrets.update(transaction, memberA, databaseSecretId, {
      value: "postgres://rotated",
      notes: null,
      changeNote: "rotate credential",
    });
    assert.equal(updated.currentVersion, 2);
    assert.equal(updated.notes, null);
    const versions = await transaction.query<{ version: number; ciphertext: Buffer }>(
      "SELECT version, value_ciphertext AS ciphertext FROM secret_versions WHERE secret_id = $1 ORDER BY version",
      [databaseSecretId],
    );
    assert.deepEqual(versions.rows.map(({ version }) => version), [1, 2]);
    assert.notDeepEqual(versions.rows[0]?.ciphertext, versions.rows[1]?.ciphertext);
    await assert.rejects(
      secrets.update(transaction, memberA, databaseSecretId, {
        value: "stale concurrent update",
        expectedVersion: 1,
      }),
      (error: unknown) => error instanceof SecretError && error.code === "VERSION_CONFLICT",
    );
    assert.equal(
      (await transaction.query<{ count: number }>(
        "SELECT count(*)::integer AS count FROM secret_versions WHERE secret_id = $1",
        [databaseSecretId],
      )).rows[0]?.count,
      2,
    );
  });

  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      secrets.create(transaction, memberA, projectA, developmentEnvironmentId, {
        key: "lower.case",
        value: "allowed only with override",
      }),
    ),
    (error: unknown) => error instanceof SecretError && error.code === "KEY_CONVENTION",
  );
  await database.withOrg(orgA, memberA, async (transaction) => {
    const override = await secrets.create(transaction, memberA, projectA, developmentEnvironmentId, {
      key: "lower.case",
      value: "explicit override",
      allowNonConformingKey: true,
    });
    assert.equal(override.key, "lower.case");
  });
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      secrets.create(transaction, memberA, projectA, developmentEnvironmentId, {
        key: "DATABASE_URL",
        value: "duplicate",
      }),
    ),
    (error: unknown) => error instanceof SecretError && error.code === "KEY_EXISTS",
  );
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      secrets.create(transaction, memberA, projectA, developmentEnvironmentId, {
        key: "TOO_LARGE",
        value: "x".repeat(65_537),
      }),
    ),
    (error: unknown) => error instanceof SecretError && error.code === "VALUE_TOO_LARGE",
  );
});

test("applies protected-environment and project-override authorization", async () => {
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      secrets.create(transaction, memberA, projectA, productionEnvironmentId, {
        key: "PRODUCTION_ONLY",
        value: "denied",
      }),
    ),
    (error: unknown) => error instanceof AuthorizationError
      && error.decision.reason === "protected_environment",
  );
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const created = await secrets.create(transaction, ownerA, projectA, productionEnvironmentId, {
      key: "PRODUCTION_ONLY",
      value: "owner-write",
    });
    assert.equal(created.currentVersion, 1);
    await transaction.query(
      `INSERT INTO project_role_overrides
        (org_id, project_id, user_id, role, created_by_user_id)
       VALUES ($1, $2, $3, 'read_only', $4)`,
      [orgA, projectA, memberA, ownerA],
    );
  });
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      secrets.update(transaction, memberA, databaseSecretId, { value: "denied by override" }),
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

test("bulk-sets atomically and soft-deletes without removing ciphertext history", async () => {
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      secrets.bulkSet(transaction, memberA, projectA, developmentEnvironmentId, [
        { key: "ROLLBACK_FIRST", value: "first" },
        { key: "ROLLBACK_LARGE", value: "x".repeat(65_537) },
      ]),
    ),
    (error: unknown) => error instanceof SecretError && error.code === "VALUE_TOO_LARGE",
  );
  await database.withOrg(orgA, memberA, async (transaction) => {
    assert.equal(
      (await transaction.query("SELECT 1 FROM secrets WHERE key = 'ROLLBACK_FIRST'")).rowCount,
      0,
    );
    const result = await secrets.bulkSet(transaction, memberA, projectA, developmentEnvironmentId, [
      { key: "DATABASE_URL", value: "postgres://bulk-update", changeNote: "bulk refresh" },
      { key: "CACHE_URL", value: "redis://cache" },
      { key: "FEATURE_FLAG", value: "enabled" },
    ]);
    assert.deepEqual(result.map(({ key }) => key), ["DATABASE_URL", "CACHE_URL", "FEATURE_FLAG"]);
    assert.equal(result[0]?.currentVersion, 3);
    await assert.rejects(
      secrets.bulkSet(transaction, memberA, projectA, developmentEnvironmentId, [
        { key: "DUPLICATE", value: "one" },
        { key: "DUPLICATE", value: "two" },
      ]),
      (error: unknown) => error instanceof SecretError && error.code === "INVALID_INPUT",
    );
    const feature = result.find(({ key }) => key === "FEATURE_FLAG");
    assert.ok(feature);
    await secrets.delete(transaction, memberA, feature.id);
    await assert.rejects(
      secrets.get(transaction, memberA, feature.id),
      (error: unknown) => error instanceof SecretError && error.code === "NOT_FOUND",
    );
    assert.equal(
      (await transaction.query("SELECT count(*)::integer AS count FROM secret_versions WHERE secret_id = $1", [feature.id])).rows[0]?.count,
      1,
    );
    const recreated = await secrets.create(
      transaction,
      memberA,
      projectA,
      developmentEnvironmentId,
      { key: "FEATURE_FLAG", value: "disabled", changeNote: "recreate after deletion" },
    );
    assert.equal(recreated.id, feature.id);
    assert.equal(recreated.currentVersion, 2);
    assert.equal((await secrets.get(transaction, memberA, recreated.id)).value, "disabled");
  });
});

test("forced RLS prevents cross-tenant secret access", async () => {
  const otherSecretId = await database.withOrg(orgB, ownerB, async (transaction) => {
    const environment = await transaction.query<{ id: string }>(
      "SELECT id FROM environments WHERE project_id = $1 ORDER BY display_order LIMIT 1",
      [projectB],
    );
    const environmentId = environment.rows[0]?.id;
    assert.ok(environmentId);
    return (await secrets.create(transaction, ownerB, projectB, environmentId, {
      key: "OTHER_TENANT",
      value: "isolated",
    })).id;
  });
  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) => secrets.get(transaction, ownerA, otherSecretId)),
    (error: unknown) => error instanceof SecretError && error.code === "NOT_FOUND",
  );
});

test("records secret actions without plaintext or ciphertext metadata", async () => {
  const events = await database.withOrg(orgA, ownerA, (transaction) =>
    transaction.query<{ action: string; metadata: Record<string, unknown> }>(
      "SELECT action, metadata FROM audit_events WHERE action LIKE 'secret.%' ORDER BY id",
    ),
  );
  const actions = events.rows.map(({ action }) => action);
  assert.ok(actions.includes("secret.created"));
  assert.ok(actions.includes("secret.read"));
  assert.ok(actions.includes("secret.updated"));
  assert.ok(actions.includes("secret.deleted"));
  const encodedMetadata = JSON.stringify(events.rows.map(({ metadata }) => metadata));
  assert.doesNotMatch(encodedMetadata, /postgres:\/\/|redis:\/\/|owner-write|explicit override|enabled/);
  assert.doesNotMatch(encodedMetadata, /ciphertext|nonce|auth_tag/i);
});
