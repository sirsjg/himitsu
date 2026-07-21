import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AuthError,
  PasswordHasher,
  clearSessionCookieHeaders,
  csrfCookie,
  sessionCookie,
  sessionCookieHeaders,
} from "../src/index.js";

test("hashes passwords with Argon2id and verifies without exposing the password", async () => {
  const hasher = new PasswordHasher();
  const hash = await hasher.hash("correct horse battery staple");
  assert.match(hash, /^\$argon2id\$/);
  assert.equal(hash.includes("correct horse"), false);
  assert.equal(await hasher.verify(hash, "correct horse battery staple"), true);
  assert.equal(await hasher.verify(hash, "incorrect password"), false);
});

test("enforces password length limits", async () => {
  const hasher = new PasswordHasher();
  await assert.rejects(
    hasher.hash("too-short"),
    (error: unknown) => error instanceof AuthError && error.code === "INVALID_INPUT",
  );
});

test("defines host-only secure SameSite cookies", () => {
  assert.deepEqual(sessionCookie, {
    name: "__Host-himitsu_session",
    options: { httpOnly: true, secure: true, sameSite: "Strict", path: "/" },
  });
  assert.deepEqual(csrfCookie, {
    name: "__Host-himitsu_csrf",
    options: { httpOnly: false, secure: true, sameSite: "Strict", path: "/" },
  });
  const [session, csrf] = sessionCookieHeaders({
    sessionToken: "session-token",
    csrfToken: "csrf-token",
    expiresAt: new Date(Date.now() + 60_000),
    user: { id: "user-1", email: "person@example.com" },
  });
  assert.match(session, /^__Host-himitsu_session=.*; Path=\/; Max-Age=\d+; Secure; HttpOnly; SameSite=Strict$/);
  assert.match(csrf, /^__Host-himitsu_csrf=.*; Path=\/; Max-Age=\d+; Secure; SameSite=Strict$/);
  assert.equal(csrf.includes("HttpOnly"), false);
  assert.deepEqual(
    clearSessionCookieHeaders().map((header) => header.includes("Max-Age=0")),
    [true, true],
  );
});
