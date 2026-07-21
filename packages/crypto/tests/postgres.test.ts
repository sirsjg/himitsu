import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { Pool } from "pg";
import {
  EnvelopeEncryptionService,
  LocalMasterKey,
  PostgresDataKeyStore,
  type SecretEncryptionContext,
} from "../src/index.js";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString === undefined) {
  throw new Error("TEST_DATABASE_URL is required for PostgreSQL crypto integration tests");
}

const pool = new Pool({ connectionString, max: 4 });
const orgId = randomUUID();
const context: SecretEncryptionContext = {
  orgId,
  projectId: randomUUID(),
  environmentId: randomUUID(),
  secretId: randomUUID(),
  recordVersion: 1,
};

before(async () => {
  await pool.query("INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)", [
    orgId,
    "Crypto integration",
    `crypto-${orgId}`,
  ]);
});

after(async () => {
  await pool.query("DELETE FROM org_encryption_keys WHERE org_id = $1", [orgId]);
  await pool.query("DELETE FROM organizations WHERE id = $1", [orgId]);
  await pool.end();
});

test("persists only wrapped keys and rotates atomically in PostgreSQL", async () => {
  const store = new PostgresDataKeyStore(pool);
  const crypto = new EnvelopeEncryptionService(
    store,
    new LocalMasterKey("integration-master-v1", randomBytes(32)),
  );
  const first = await crypto.encrypt(Buffer.from("first-value"), context);

  const persisted = await pool.query<{
    version: number;
    status: string;
    wrapped_length: number;
    nonce_length: number;
    tag_length: number;
  }>(
    `SELECT version, status, octet_length(wrapped_dek) AS wrapped_length,
            octet_length(wrap_nonce) AS nonce_length, octet_length(wrap_tag) AS tag_length
     FROM org_encryption_keys WHERE org_id = $1`,
    [orgId],
  );
  assert.deepEqual(persisted.rows, [
    { version: 1, status: "active", wrapped_length: 32, nonce_length: 12, tag_length: 16 },
  ]);

  assert.equal(await crypto.rotateDataKey(orgId), 2);
  const second = await crypto.encrypt(
    Buffer.from("second-value"),
    { ...context, recordVersion: 2 },
  );
  assert.equal(first.keyVersion, 1);
  assert.equal(second.keyVersion, 2);
  assert.equal((await crypto.decrypt(first, context)).toString(), "first-value");

  const versions = await pool.query<{ version: number; status: string }>(
    "SELECT version, status FROM org_encryption_keys WHERE org_id = $1 ORDER BY version",
    [orgId],
  );
  assert.deepEqual(versions.rows, [
    { version: 1, status: "retired" },
    { version: 2, status: "active" },
  ]);
  crypto.clearKeyCache();
});
