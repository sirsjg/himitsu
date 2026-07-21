import assert from "node:assert/strict";
import { after, test } from "node:test";
import { Pool } from "pg";
import { AuthError, AuthService, type TokenDelivery } from "../src/index.js";

const connectionString = process.env.TEST_DATABASE_URL;
if (connectionString === undefined) throw new Error("TEST_DATABASE_URL is required");
const pool = new Pool({ connectionString, max: 4 });

class CapturingDelivery implements TokenDelivery {
  readonly verifications: Array<{ email: string; token: string }> = [];
  readonly resets: Array<{ email: string; token: string }> = [];
  async sendEmailVerification(email: string, token: string): Promise<void> {
    this.verifications.push({ email, token });
  }
  async sendPasswordReset(email: string, token: string): Promise<void> {
    this.resets.push({ email, token });
  }
}

const delivery = new CapturingDelivery();
const auth = new AuthService(pool, delivery);

after(async () => pool.end());

test("signup normalizes email, hashes password, and stores only a verification-token hash", async () => {
  await auth.signup("  Person@Example.COM ", "initial password phrase");
  assert.equal(delivery.verifications.length, 1);
  assert.equal(delivery.verifications[0]?.email, "person@example.com");
  const user = await pool.query<{ email: string; password_hash: string }>(
    "SELECT email, password_hash FROM users WHERE email_normalized = $1",
    ["person@example.com"],
  );
  assert.equal(user.rows[0]?.email, "person@example.com");
  assert.match(user.rows[0]?.password_hash ?? "", /^\$argon2id\$/);
  assert.equal(user.rows[0]?.password_hash.includes("initial password phrase"), false);
  const token = delivery.verifications[0]?.token ?? "";
  const stored = await pool.query<{ token_hash: Buffer }>("SELECT token_hash FROM email_verification_tokens");
  assert.equal(stored.rows[0]?.token_hash.toString("utf8").includes(token), false);
  await assert.rejects(
    auth.signup("person@example.com", "another password phrase"),
    (error: unknown) => error instanceof AuthError && error.code === "EMAIL_EXISTS",
  );
});

test("requires verification, creates a hashed session, enforces CSRF, and logs out", async () => {
  await assert.rejects(
    auth.login("person@example.com", "initial password phrase"),
    (error: unknown) => error instanceof AuthError && error.code === "EMAIL_NOT_VERIFIED",
  );
  await auth.verifyEmail(delivery.verifications[0]?.token ?? "");
  await assert.rejects(
    auth.verifyEmail(delivery.verifications[0]?.token ?? ""),
    (error: unknown) => error instanceof AuthError && error.code === "INVALID_TOKEN",
  );
  const login = await auth.login("person@example.com", "initial password phrase", {
    ip: "203.0.113.9",
    userAgent: "auth-integration/1",
  });
  const session = await auth.authenticate(login.sessionToken);
  auth.verifyCsrf(session, login.csrfToken);
  assert.throws(
    () => auth.verifyCsrf(session, "wrong-csrf-token"),
    (error: unknown) => error instanceof AuthError && error.code === "INVALID_CSRF",
  );
  const stored = await pool.query<{ token_hash: Buffer; csrf_hash: Buffer; ip: string }>(
    "SELECT token_hash, csrf_hash, host(ip) AS ip FROM sessions WHERE id = $1",
    [session.sessionId],
  );
  assert.equal(stored.rows[0]?.token_hash.toString("utf8").includes(login.sessionToken), false);
  assert.equal(stored.rows[0]?.csrf_hash.toString("utf8").includes(login.csrfToken), false);
  assert.equal(stored.rows[0]?.ip, "203.0.113.9");
  await assert.rejects(
    auth.logout(login.sessionToken, "wrong-csrf-token"),
    (error: unknown) => error instanceof AuthError && error.code === "INVALID_CSRF",
  );
  await auth.logout(login.sessionToken, login.csrfToken);
  await assert.rejects(
    auth.authenticate(login.sessionToken),
    (error: unknown) => error instanceof AuthError && error.code === "INVALID_SESSION",
  );
});

test("password reset is enumeration-safe, single-use, and revokes sessions", async () => {
  await auth.requestPasswordReset("missing@example.com");
  assert.equal(delivery.resets.length, 0);
  const oldSession = await auth.login("person@example.com", "initial password phrase");
  await auth.requestPasswordReset("Person@Example.com");
  assert.equal(delivery.resets.length, 1);
  const resetToken = delivery.resets[0]?.token ?? "";
  await auth.resetPassword(resetToken, "replacement password phrase");
  await assert.rejects(
    auth.resetPassword(resetToken, "second replacement phrase"),
    (error: unknown) => error instanceof AuthError && error.code === "INVALID_TOKEN",
  );
  await assert.rejects(
    auth.authenticate(oldSession.sessionToken),
    (error: unknown) => error instanceof AuthError && error.code === "INVALID_SESSION",
  );
  await assert.rejects(
    auth.login("person@example.com", "initial password phrase"),
    (error: unknown) => error instanceof AuthError && error.code === "INVALID_CREDENTIALS",
  );
  const newSession = await auth.login("person@example.com", "replacement password phrase");
  assert.equal((await auth.authenticate(newSession.sessionToken)).email, "person@example.com");
});
