import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ProjectError,
  normalizeProjectSlug,
  validateDefaultEnvironments,
} from "../src/index.js";

test("normalizes project and default-environment slugs", () => {
  assert.equal(normalizeProjectSlug("  Customer-API "), "customer-api");
  assert.deepEqual(validateDefaultEnvironments(undefined), ["development", "staging", "production"]);
  assert.deepEqual(validateDefaultEnvironments(["Dev", "Prod"]), ["dev", "prod"]);
});

test("rejects invalid slugs and duplicate environment settings", () => {
  for (const operation of [
    () => normalizeProjectSlug("not valid"),
    () => validateDefaultEnvironments([]),
    () => validateDefaultEnvironments(["prod", "PROD"]),
  ]) {
    assert.throws(
      operation,
      (error: unknown) => error instanceof ProjectError && error.code === "INVALID_INPUT",
    );
  }
});
