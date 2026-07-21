import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { Pool } from "pg";
import { TransactionalAuditLog } from "../src/index.js";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString === undefined) {
  throw new Error("TEST_DATABASE_URL is required for PostgreSQL audit integration tests");
}

const pool = new Pool({ connectionString, max: 4 });
const orgId = randomUUID();
const userId = randomUUID();
const apiKeyId = randomUUID();
const projectId = randomUUID();
const environmentId = randomUUID();
const audit = new TransactionalAuditLog(pool);

before(async () => {
  await pool.query("INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)", [
    orgId,
    "Audit integration",
    `audit-${orgId}`,
  ]);
  await pool.query("INSERT INTO users (id, email) VALUES ($1, $2)", [
    userId,
    `${userId}@example.com`,
  ]);
  await pool.query(
    "INSERT INTO api_keys (id, org_id, name, prefix, token_hash, access) VALUES ($1, $2, $3, $4, $5, $6)",
    [apiKeyId, orgId, "Audit test", "himi_audit123", Buffer.from("audit-key-hash"), "read_only"],
  );
});

after(async () => {
  await pool.query("DELETE FROM audit_events WHERE false");
  await pool.end();
});

test("commits a sensitive mutation and its complete audit event together", async () => {
  const tagId = randomUUID();
  await audit.execute(
    {
      orgId,
      actor: { type: "user", id: userId },
      action: "membership.role_changed",
      resource: { type: "membership", id: userId },
      projectId,
      environmentId,
      ip: "203.0.113.42",
      userAgent: "himitsu-test/1",
      before: { role: "member" },
      after: { role: "admin" },
    },
    async (transaction) => {
      await transaction.query(
        "INSERT INTO tags (id, org_id, name, color) VALUES ($1, $2, $3, $4)",
        [tagId, orgId, "audited-mutation", "#112233"],
      );
    },
  );

  const result = await pool.query<{
    actor_type: string;
    actor_user_id: string;
    action: string;
    resource_type: string;
    resource_id: string;
    ip: string;
    user_agent: string;
    project_id: string;
    environment_id: string;
    occurred_at: Date;
    metadata: { before: { role: string }; after: { role: string } };
  }>(
    `SELECT actor_type, actor_user_id, action, resource_type, resource_id,
            project_id, environment_id, host(ip) AS ip, user_agent, occurred_at, metadata
     FROM audit_events WHERE org_id = $1 AND action = $2`,
    [orgId, "membership.role_changed"],
  );
  assert.equal(result.rows.length, 1);
  const row = result.rows[0];
  assert.ok(row?.occurred_at instanceof Date);
  assert.deepEqual(row === undefined ? row : { ...row, occurred_at: "recorded" }, {
    actor_type: "user",
    actor_user_id: userId,
    action: "membership.role_changed",
    resource_type: "membership",
    resource_id: userId,
    project_id: projectId,
    environment_id: environmentId,
    ip: "203.0.113.42",
    user_agent: "himitsu-test/1",
    occurred_at: "recorded",
    metadata: { before: { role: "member" }, after: { role: "admin" } },
  });
});

test("rolls back the sensitive mutation when audit insertion fails", async () => {
  const tagId = randomUUID();
  await assert.rejects(
    audit.execute(
      {
        orgId,
        actor: { type: "user", id: randomUUID() },
        action: "membership.role_changed",
        resource: { type: "membership", id: randomUUID() },
        details: { reason: "integration_test" },
      },
      async (transaction) => {
        await transaction.query(
          "INSERT INTO tags (id, org_id, name, color) VALUES ($1, $2, $3, $4)",
          [tagId, orgId, "must-rollback", "#445566"],
        );
      },
    ),
  );
  const tag = await pool.query("SELECT id FROM tags WHERE id = $1", [tagId]);
  assert.equal(tag.rowCount, 0);
});

test("records system and API-key actors", async () => {
  await audit.record({
    orgId,
    actor: { type: "system" },
    action: "auth.login_failed",
    resource: { type: "authentication", id: "attempt-7" },
    details: { reason: "invalid_credentials" },
  });
  await audit.record({
    orgId,
    actor: { type: "api_key", id: apiKeyId },
    action: "api_key.used",
    resource: { type: "api_key", id: apiKeyId },
    details: { outcome: "allowed" },
  });
  const actors = await pool.query<{ actor_type: string }>(
    "SELECT actor_type FROM audit_events WHERE org_id = $1 ORDER BY id DESC LIMIT 2",
    [orgId],
  );
  assert.deepEqual(actors.rows.map(({ actor_type }) => actor_type), ["api_key", "system"]);
});

test("database trigger rejects audit updates and deletes", async () => {
  await assert.rejects(
    pool.query("UPDATE audit_events SET action = 'auth.logout' WHERE org_id = $1", [orgId]),
    /append-only/,
  );
  await assert.rejects(
    pool.query("DELETE FROM audit_events WHERE org_id = $1", [orgId]),
    /append-only/,
  );
});
