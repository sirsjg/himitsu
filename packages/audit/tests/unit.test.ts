import assert from "node:assert/strict";
import { test } from "node:test";
import type { Pool } from "pg";
import { AuditError, TransactionalAuditLog, type AuditEventInput } from "../src/index.js";

const baseEvent: AuditEventInput = {
  orgId: "org-alpha",
  actor: { type: "system" },
  action: "auth.login_failed",
  resource: { type: "authentication", id: "attempt-1" },
  details: { reason: "invalid_credentials", attempt: 2 },
};

function unreachablePool(): Pool {
  return {
    connect: async () => {
      throw new Error("metadata validation unexpectedly reached the database");
    },
  } as unknown as Pool;
}

test("rejects secret-bearing metadata before opening a transaction", async () => {
  const audit = new TransactionalAuditLog(unreachablePool());
  for (const unsafe of [
    { value: "plaintext" },
    { nested: { password_hash: "hash" } },
    { authorization: "Bearer credential" },
    { change: { secret_token: "token" } },
    { ciphertext: "encoded" },
  ]) {
    await assert.rejects(
      audit.record({ ...baseEvent, details: unsafe }),
      (error: unknown) => error instanceof AuditError && error.code === "UNSAFE_METADATA",
    );
  }
});

test("rejects invalid event identities before opening a transaction", async () => {
  const audit = new TransactionalAuditLog(unreachablePool());
  await assert.rejects(
    audit.record({ ...baseEvent, orgId: "" }),
    (error: unknown) => error instanceof AuditError && error.code === "INVALID_EVENT",
  );
  await assert.rejects(
    audit.record({
      ...baseEvent,
      actor: { type: "user", id: "" },
    }),
    (error: unknown) => error instanceof AuditError && error.code === "INVALID_EVENT",
  );
  await assert.rejects(
    audit.record({
      ...baseEvent,
      action: "secret.read",
      resource: { type: "secret" },
    }),
    (error: unknown) => error instanceof AuditError && error.code === "INVALID_EVENT",
  );
});

test("limits metadata depth, collection size, and encoded size", async () => {
  const audit = new TransactionalAuditLog(unreachablePool());
  let nested: Record<string, unknown> = { safe: true };
  for (let index = 0; index < 10; index += 1) nested = { nested };

  for (const unsafe of [
    nested,
    { items: Array.from({ length: 101 }, () => true) },
    { note: "x".repeat(65 * 1024) },
  ]) {
    await assert.rejects(
      audit.record({
        ...baseEvent,
        details: unsafe as NonNullable<AuditEventInput["details"]>,
      }),
      (error: unknown) => error instanceof AuditError && error.code === "UNSAFE_METADATA",
    );
  }
});
