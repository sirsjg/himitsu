import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { TransactionalAuditLog } from "@himitsu/audit";
import { Pool } from "pg";
import {
  TenancyError,
  TenantDatabase,
  TenancyService,
  type InvitationDelivery,
} from "../src/index.js";

const adminConnectionString = process.env.TEST_DATABASE_URL;
const appConnectionString = process.env.TEST_APP_DATABASE_URL;
if (adminConnectionString === undefined || appConnectionString === undefined) {
  throw new Error("TEST_DATABASE_URL and TEST_APP_DATABASE_URL are required");
}

const adminPool = new Pool({ connectionString: adminConnectionString, max: 2 });
const appPool = new Pool({ connectionString: appConnectionString, max: 6 });
const database = new TenantDatabase(appPool);
const audit = new TransactionalAuditLog(appPool);

class CapturingDelivery implements InvitationDelivery {
  readonly messages: Array<{
    email: string;
    organizationName: string;
    inviterUserId: string;
    token: string;
  }> = [];

  async sendOrganizationInvitation(message: (typeof this.messages)[number]): Promise<void> {
    this.messages.push(message);
  }
}

const delivery = new CapturingDelivery();
const tenancy = new TenancyService(database, delivery, audit);
const userA = randomUUID();
const userB = randomUUID();
const userC = randomUUID();
const sessionA = randomUUID();
const sessionB = randomUUID();
const sessionC = randomUUID();
let orgA: string;
let orgASecond: string;
let orgB: string;

before(async () => {
  for (const [id, email] of [
    [userA, "a@example.com"],
    [userB, "b@example.com"],
    [userC, "c@example.com"],
  ]) {
    await adminPool.query(
      "INSERT INTO users (id, email, email_verified_at) VALUES ($1, $2, now())",
      [id, email],
    );
  }
  for (const [id, userId] of [[sessionA, userA], [sessionB, userB], [sessionC, userC]]) {
    await adminPool.query(
      `INSERT INTO sessions (id, user_id, token_hash, csrf_hash, expires_at)
       VALUES ($1, $2, $3, $4, now() + interval '1 day')`,
      [id, userId, createHash("sha256").update(randomBytes(32)).digest(), randomBytes(32)],
    );
  }
});

after(async () => {
  await appPool.end();
  await adminPool.end();
});

test("creates organizations and returns switcher options for multiple memberships", async () => {
  orgA = (await tenancy.createOrganization(userA, "Alpha", "alpha")).id;
  orgASecond = (await tenancy.createOrganization(userA, "Alpha Labs", "alpha-labs")).id;
  orgB = (await tenancy.createOrganization(userB, "Beta", "beta")).id;

  const options = await tenancy.listOrganizations(userA, orgASecond);
  assert.deepEqual(options, [
    { id: orgA, name: "Alpha", slug: "alpha", role: "owner", active: false },
    { id: orgASecond, name: "Alpha Labs", slug: "alpha-labs", role: "owner", active: true },
  ]);
  await assert.rejects(
    tenancy.createOrganization(userC, "Duplicate", "alpha"),
    (error: unknown) => error instanceof TenancyError && error.code === "SLUG_EXISTS",
  );
  const events = await database.withOrg(orgA, userA, (transaction) =>
    transaction.query<{ action: string }>(
      "SELECT action FROM audit_events ORDER BY id",
    ),
  );
  assert.deepEqual(events.rows.map(({ action }) => action), ["organization.created"]);
});

test("invites by email, enforces inviter permissions, and accepts into multiple organizations", async () => {
  await tenancy.inviteMember({ orgId: orgA, inviterUserId: userA, email: " B@Example.com ", role: "member" });
  assert.equal(delivery.messages[0]?.email, "b@example.com");
  await assert.rejects(
    tenancy.inviteMember({ orgId: orgA, inviterUserId: userA, email: "b@example.com", role: "member" }),
    (error: unknown) => error instanceof TenancyError && error.code === "INVITATION_EXISTS",
  );
  const bToken = delivery.messages[0]?.token ?? "";
  const stored = await database.withOrg(orgA, userA, (transaction) =>
    transaction.query<{ token_hash: Buffer }>(
      "SELECT token_hash FROM organization_invitations WHERE email_normalized = 'b@example.com'",
    ),
  );
  assert.equal(stored.rows[0]?.token_hash.toString("utf8").includes(bToken), false);
  assert.equal(await tenancy.acceptInvitation(bToken, userB, "b@example.com"), orgA);

  const bOptions = await tenancy.listOrganizations(userB, null);
  assert.deepEqual(bOptions.map(({ slug, role }) => ({ slug, role })), [
    { slug: "alpha", role: "member" },
    { slug: "beta", role: "owner" },
  ]);
  await assert.rejects(
    tenancy.inviteMember({ orgId: orgA, inviterUserId: userB, email: "c@example.com", role: "member" }),
    (error: unknown) => error instanceof TenancyError && error.code === "INVITE_FORBIDDEN",
  );

  await tenancy.inviteMember({ orgId: orgA, inviterUserId: userA, email: "c@example.com", role: "read_only" });
  const cToken = delivery.messages.at(-1)?.token ?? "";
  await assert.rejects(
    tenancy.acceptInvitation(cToken, userB, "b@example.com"),
    (error: unknown) => error instanceof TenancyError && error.code === "INVITATION_EMAIL_MISMATCH",
  );
  assert.equal(await tenancy.acceptInvitation(cToken, userC, "c@example.com"), orgA);
  await assert.rejects(
    tenancy.inviteMember({ orgId: orgA, inviterUserId: userA, email: "c@example.com", role: "member" }),
    (error: unknown) => error instanceof TenancyError && error.code === "ALREADY_MEMBER",
  );
});

test("switches the active organization only for an active membership", async () => {
  await tenancy.switchOrganization(sessionB, userB, orgA);
  const options = await tenancy.listOrganizations(userB, orgA);
  assert.equal(options.find(({ id }) => id === orgA)?.active, true);
  await assert.rejects(
    tenancy.switchOrganization(sessionC, userC, orgB),
    (error: unknown) => error instanceof TenancyError && error.code === "MEMBERSHIP_REQUIRED",
  );
});

test("centrally scopes every query to the active tenant and rejects cross-tenant access", async () => {
  await database.withOrg(orgA, userB, async (transaction) => {
    await transaction.query(
      "INSERT INTO tags (org_id, name, color) VALUES ($1, 'alpha-tag', '#112233')",
      [orgA],
    );
  });
  await database.withOrg(orgB, userB, async (transaction) => {
    await transaction.query(
      "INSERT INTO tags (org_id, name, color) VALUES ($1, 'beta-tag', '#445566')",
      [orgB],
    );
  });

  const activeRows = await database.withActiveOrganization(sessionB, userB, (transaction) =>
    transaction.query<{ name: string }>("SELECT name FROM tags ORDER BY name"),
  );
  assert.deepEqual(activeRows.rows.map(({ name }) => name), ["alpha-tag"]);
  const activeMemberships = await database.withActiveOrganization(sessionB, userB, (transaction) =>
    transaction.query<{ org_id: string }>("SELECT org_id FROM memberships ORDER BY org_id"),
  );
  assert.equal(activeMemberships.rows.length, 3);
  assert.deepEqual(new Set(activeMemberships.rows.map(({ org_id }) => org_id)), new Set([orgA]));

  const betaRows = await database.withOrg(orgB, userB, (transaction) =>
    transaction.query<{ name: string }>("SELECT name FROM tags ORDER BY name"),
  );
  assert.deepEqual(betaRows.rows.map(({ name }) => name), ["beta-tag"]);

  await assert.rejects(
    database.withOrg(orgA, userB, (transaction) =>
      transaction.query(
        "INSERT INTO tags (org_id, name, color) VALUES ($1, 'cross-tenant', '#778899')",
        [orgB],
      ),
    ),
    (error: unknown) => (error as { code?: string }).code === "42501",
  );
  await assert.rejects(
    database.withOrg(orgB, userA, (transaction) => transaction.query("SELECT * FROM tags")),
    (error: unknown) => error instanceof TenancyError && error.code === "MEMBERSHIP_REQUIRED",
  );
  const unscoped = await appPool.query("SELECT * FROM tags");
  assert.equal(unscoped.rowCount, 0);
});
