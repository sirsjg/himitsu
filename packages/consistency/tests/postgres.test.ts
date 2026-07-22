import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { TransactionalAuditLog } from "@himitsu/audit";
import { AuthorizationContextResolver, AuthorizationError } from "@himitsu/authz";
import { LocalMasterKey } from "@himitsu/crypto";
import { SecretService } from "@himitsu/secrets";
import { TenantDatabase } from "@himitsu/tenancy";
import { Pool } from "pg";
import { ConsistencyError, ConsistencyService } from "../src/index.js";

const adminConnectionString = process.env.TEST_DATABASE_URL;
const appConnectionString = process.env.TEST_APP_DATABASE_URL;
if (adminConnectionString === undefined || appConnectionString === undefined) {
  throw new Error("TEST_DATABASE_URL and TEST_APP_DATABASE_URL are required");
}

const adminPool = new Pool({ connectionString: adminConnectionString, max: 2 });
const appPool = new Pool({ connectionString: appConnectionString, max: 10 });
const database = new TenantDatabase(appPool);
const audit = new TransactionalAuditLog(appPool);
const resolver = new AuthorizationContextResolver();
const secretService = new SecretService(
  resolver,
  audit,
  new LocalMasterKey("consistency-integration-v1", Buffer.alloc(32, 11)),
);
const consistency = new ConsistencyService(resolver, secretService, audit);
const orgA = randomUUID();
const orgB = randomUUID();
const ownerA = randomUUID();
const memberA = randomUUID();
const readerA = randomUUID();
const ownerB = randomUUID();
const projectA = randomUUID();
const projectB = randomUUID();
let developmentId: string;
let stagingId: string;
let productionId: string;
let placeholderSecretId: string;

before(async () => {
  await adminPool.query(
    `INSERT INTO users (id, email, email_verified_at) VALUES
      ($1, 'consistency-owner-a@example.com', now()), ($2, 'consistency-member-a@example.com', now()),
      ($3, 'consistency-reader-a@example.com', now()), ($4, 'consistency-owner-b@example.com', now())`,
    [ownerA, memberA, readerA, ownerB],
  );
  await adminPool.query(
    "INSERT INTO organizations (id, name, slug) VALUES ($1, 'Consistency Alpha', 'consistency-alpha'), ($2, 'Consistency Beta', 'consistency-beta')",
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
       VALUES ($1, $2, 'Consistency Project', 'consistency-project',
         '{"defaultEnvironments":["development","staging","production"]}', $3)`,
      [projectA, orgA, ownerA],
    );
    const environments = await transaction.query<{ id: string; slug: string }>(
      "SELECT id, slug FROM environments WHERE project_id = $1",
      [projectA],
    );
    developmentId = environments.rows.find(({ slug }) => slug === "development")?.id ?? "";
    stagingId = environments.rows.find(({ slug }) => slug === "staging")?.id ?? "";
    productionId = environments.rows.find(({ slug }) => slug === "production")?.id ?? "";
    assert.ok(developmentId && stagingId && productionId);
    await secretService.bulkSet(transaction, ownerA, projectA, developmentId, [
      { key: "DATABASE_URL", value: "postgres://development" },
      { key: "EMPTY_VALUE", value: "   " },
      { key: "PLACEHOLDER", value: "changeme" },
      { key: "mixedCase", value: "real", allowNonConformingKey: true },
    ]);
    await secretService.bulkSet(transaction, ownerA, projectA, stagingId, [
      { key: "database_url", value: "postgres://staging", allowNonConformingKey: true },
      { key: "EMPTY_VALUE", value: "configured" },
      { key: "PLACEHOLDER", value: "configured" },
      { key: "ONLY_STAGING", value: "real" },
    ]);
    const production = await secretService.bulkSet(transaction, ownerA, projectA, productionId, [
      { key: "DATABASE_URL", value: "postgres://production" },
      { key: "EMPTY_VALUE", value: "configured" },
      { key: "PLACEHOLDER", value: "<replace-me>" },
    ]);
    placeholderSecretId = production.find(({ key }) => key === "PLACEHOLDER")?.id ?? "";
    assert.ok(placeholderSecretId);
  });
  await database.withOrg(orgB, ownerB, (transaction) => transaction.query(
    `INSERT INTO projects (id, org_id, name, slug, settings, created_by_user_id)
     VALUES ($1, $2, 'Other Consistency', 'other-consistency', '{}', $3)`,
    [projectB, orgB, ownerB],
  ));
});

after(async () => {
  await appPool.end();
  await adminPool.end();
});

test("detects every drift class with severity and no plaintext findings", async () => {
  const report = await database.withOrg(orgA, readerA, (transaction) =>
    consistency.compute(transaction, readerA, projectA),
  );
  assert.equal(report.cached, false);
  assert.equal(report.sourceFingerprint.length, 64);
  assert.deepEqual(new Set(report.findings.map(({ type }) => type)), new Set([
    "missing_key", "empty_value", "placeholder_value", "naming_violation", "case_duplicate",
  ]));
  assert.equal(report.findings.filter(({ type }) => type === "missing_key").length, 2);
  assert.equal(report.findings.filter(({ type }) => type === "placeholder_value").length, 2);
  assert.equal(report.findings.find(({ type }) => type === "empty_value")?.severity, "error");
  assert.equal(report.findings.find(({ type }) => type === "naming_violation")?.severity, "warning");
  assert.equal(report.counts.error + report.counts.warning, report.findings.length);
  const encoded = JSON.stringify(report.findings);
  assert.doesNotMatch(encoded, /postgres:\/\/|changeme|replace-me|configured/);
  assert.equal(report.findings.every(({ disposition }) => disposition === null), true);
  assert.equal(report.environments.length, 3);
  assert.equal(report.summary.healthy, false);
  assert.equal(report.summary.exitCode, 1);
  assert.equal(report.summary.activeFindings, report.findings.length);
  const emptyRow = report.matrix.find(({ key }) => key === "EMPTY_VALUE");
  assert.ok(emptyRow);
  assert.equal(emptyRow.cells.find(({ environmentId }) => environmentId === developmentId)?.state, "empty");
  assert.equal(emptyRow.cells.find(({ environmentId }) => environmentId === stagingId)?.state, "present");
  assert.equal(emptyRow.cells.find(({ environmentId }) => environmentId === productionId)?.state, "present");
  const stagingOnly = report.matrix.find(({ key }) => key === "ONLY_STAGING");
  assert.equal(stagingOnly?.cells.filter(({ state }) => state === "missing").length, 2);
  assert.doesNotMatch(JSON.stringify(report.matrix), /postgres:\/\/|changeme|replace-me|configured/);
});

test("reuses cache until a source version changes and never caches plaintext", async () => {
  const auditCountBefore = await database.withOrg(orgA, ownerA, (transaction) =>
    transaction.query<{ count: number }>("SELECT count(*)::integer AS count FROM audit_events WHERE action = 'secret.read'"),
  );
  const cached = await database.withOrg(orgA, readerA, (transaction) =>
    consistency.compute(transaction, readerA, projectA),
  );
  assert.equal(cached.cached, true);
  const auditCountAfter = await database.withOrg(orgA, ownerA, (transaction) =>
    transaction.query<{ count: number }>("SELECT count(*)::integer AS count FROM audit_events WHERE action = 'secret.read'"),
  );
  assert.equal(auditCountAfter.rows[0]?.count, auditCountBefore.rows[0]?.count);
  await database.withOrg(orgA, ownerA, (transaction) => secretService.update(
    transaction,
    ownerA,
    placeholderSecretId,
    { value: "configured-production", changeNote: "resolve placeholder" },
  ));
  const refreshed = await database.withOrg(orgA, readerA, (transaction) =>
    consistency.compute(transaction, readerA, projectA),
  );
  assert.equal(refreshed.cached, false);
  assert.notEqual(refreshed.sourceFingerprint, cached.sourceFingerprint);
  assert.equal(refreshed.findings.filter(({ type }) => type === "placeholder_value").length, 1);
  const persisted = await database.withOrg(orgA, ownerA, (transaction) =>
    transaction.query<{ findings: unknown }>("SELECT findings FROM consistency_report_cache WHERE project_id = $1", [projectA]),
  );
  assert.doesNotMatch(JSON.stringify(persisted.rows[0]?.findings), /configured-production|changeme|postgres:\/\//);
});

test("acknowledges, ignores, clears, and permission-checks finding states", async () => {
  const report = await database.withOrg(orgA, memberA, (transaction) =>
    consistency.compute(transaction, memberA, projectA),
  );
  const missing = report.findings.find(({ type }) => type === "missing_key");
  const naming = report.findings.find(({ type }) => type === "naming_violation");
  assert.ok(missing && naming);
  await database.withOrg(orgA, memberA, async (transaction) => {
    const acknowledged = await consistency.setDisposition(
      transaction,
      memberA,
      projectA,
      missing.id,
      "acknowledged",
      "Known rollout gap",
    );
    assert.equal(acknowledged.disposition, "acknowledged");
    assert.equal(acknowledged.dispositionNote, "Known rollout gap");
    assert.ok(acknowledged.dispositionUpdatedAt instanceof Date);
    assert.equal(
      (await consistency.setDisposition(transaction, memberA, projectA, naming.id, "ignored")).disposition,
      "ignored",
    );
  });
  const withStates = await database.withOrg(orgA, readerA, (transaction) =>
    consistency.compute(transaction, readerA, projectA),
  );
  assert.equal(withStates.findings.find(({ id }) => id === missing.id)?.disposition, "acknowledged");
  assert.equal(withStates.findings.find(({ id }) => id === naming.id)?.disposition, "ignored");
  await assert.rejects(
    database.withOrg(orgA, readerA, (transaction) =>
      consistency.setDisposition(transaction, readerA, projectA, missing.id, "ignored")),
    (error: unknown) => error instanceof AuthorizationError,
  );
  await database.withOrg(orgA, memberA, (transaction) =>
    consistency.clearDisposition(transaction, memberA, projectA, missing.id),
  );
  await assert.rejects(
    database.withOrg(orgA, memberA, (transaction) =>
      consistency.setDisposition(transaction, memberA, projectA, randomUUID().replaceAll("-", ""), "ignored")),
    (error: unknown) => error instanceof ConsistencyError && error.code === "NOT_FOUND",
  );
});

test("forced RLS hides other projects and records disposition audit actions", async () => {
  await assert.rejects(
    database.withOrg(orgA, ownerA, (transaction) => consistency.compute(transaction, ownerA, projectB)),
    (error: unknown) => error instanceof ConsistencyError && error.code === "NOT_FOUND",
  );
  await database.withOrg(orgA, ownerA, async (transaction) => {
    const cache = await transaction.query<{ count: number }>(
      "SELECT count(*)::integer AS count FROM consistency_report_cache",
    );
    assert.equal(cache.rows[0]?.count, 1);
    const actions = await transaction.query<{ action: string }>(
      "SELECT action FROM audit_events WHERE action LIKE 'consistency.%' ORDER BY id",
    );
    assert.deepEqual(actions.rows.map(({ action }) => action), [
      "consistency.acknowledged", "consistency.ignored", "consistency.cleared",
    ]);
  });
});
