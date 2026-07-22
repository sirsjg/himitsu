import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiKeyError, tokenPrefix } from "../src/index.js";

test("extracts the identifiable prefix without accepting malformed tokens", () => {
  const prefix = "himi_0123456789abcdef";
  const token = `${prefix}_${"A".repeat(43)}`;
  assert.equal(tokenPrefix(token), prefix);
  for (const invalid of [prefix, `other_0123456789abcdef_${"A".repeat(43)}`, `${prefix}_short`]) {
    assert.throws(
      () => tokenPrefix(invalid),
      (error: unknown) => error instanceof ApiKeyError && error.code === "INVALID_TOKEN",
    );
  }
});
