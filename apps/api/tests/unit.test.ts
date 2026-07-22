import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../src/index.js";

test("API errors carry stable status and codes without exposing causes", () => {
  const error = new ApiError(401, "UNAUTHENTICATED", "Authentication required");
  assert.equal(error.statusCode, 401);
  assert.equal(error.code, "UNAUTHENTICATED");
  assert.equal(error.message, "Authentication required");
});
