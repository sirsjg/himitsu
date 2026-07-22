import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AuthorizationError,
  authorizationSnapshot,
  authorize,
  effectiveRole,
  permissionMatrix,
  permissions,
  requirePermission,
  roles,
  uiActionPermissions,
  uiActionSnapshot,
} from "../src/index.js";

test("defines a complete permission matrix for all four roles", () => {
  assert.deepEqual(Object.keys(permissionMatrix), roles);
  for (const role of roles) {
    assert.equal(new Set(permissionMatrix[role]).size, permissionMatrix[role].length);
    for (const permission of permissionMatrix[role]) assert.ok(permissions.includes(permission));
  }
  assert.equal(permissionMatrix.owner.length, permissions.length);
  assert.equal(permissionMatrix.admin.includes("org.settings.delete"), false);
  assert.equal(permissionMatrix.member.includes("secret.write"), true);
  assert.equal(permissionMatrix.member.includes("api_key.create"), false);
  assert.deepEqual(permissionMatrix.read_only.filter((item) => item.startsWith("secret.")), ["secret.read"]);
});

test("maps every UI action to the central permission evaluator", () => {
  const readOnly = { orgRole: "read_only" as const };
  const capabilities = uiActionSnapshot(readOnly);
  for (const [action, permission] of Object.entries(uiActionPermissions)) {
    assert.equal(
      capabilities[action as keyof typeof capabilities],
      authorize(readOnly, permission).allowed,
    );
  }
  assert.equal(capabilities.revealSecret, true);
  assert.equal(capabilities.editSecret, false);
  assert.equal(capabilities.createApiKey, false);
  assert.equal(Object.values(uiActionSnapshot({ orgRole: "owner" })).every(Boolean), true);
});

test("applies project overrides only as capability downgrades", () => {
  assert.equal(effectiveRole("member", "read_only"), "read_only");
  assert.equal(effectiveRole("member", "admin"), "member");
  assert.equal(authorize({ orgRole: "member", projectRole: "read_only" }, "secret.write").allowed, false);
  assert.equal(authorize({ orgRole: "member", projectRole: "read_only" }, "secret.read").allowed, true);
  assert.equal(authorize({ orgRole: "member", projectRole: "read_only" }, "project.create").allowed, true);
});

test("requires elevated effective roles to write protected environments", () => {
  const denied = authorize({ orgRole: "member", protectedEnvironment: true }, "secret.write");
  assert.deepEqual(denied, {
    allowed: false,
    permission: "secret.write",
    effectiveRole: "member",
    reason: "protected_environment",
  });
  assert.equal(authorize({ orgRole: "admin", protectedEnvironment: true }, "secret.write").allowed, true);
  assert.equal(authorize({ orgRole: "member", protectedEnvironment: true }, "secret.read").allowed, true);
});

test("uses the same central decision for API guards and UI capability snapshots", () => {
  const context = { orgRole: "read_only" as const };
  const snapshot = authorizationSnapshot(context);
  for (const permission of permissions) {
    assert.equal(snapshot[permission], authorize(context, permission).allowed);
  }
  assert.throws(
    () => requirePermission(context, "secret.write"),
    (error: unknown) => error instanceof AuthorizationError && error.code === "FORBIDDEN",
  );
  assert.doesNotThrow(() => requirePermission(context, "secret.read"));
});
