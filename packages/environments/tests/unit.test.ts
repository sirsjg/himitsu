import assert from "node:assert/strict";
import { test } from "node:test";
import {
  EnvironmentError,
  normalizeEnvironmentSlug,
  validateEnvironmentName,
} from "../src/index.js";

test("normalizes environment names and slugs", () => {
  assert.equal(normalizeEnvironmentSlug(" Preview-02 "), "preview-02");
  assert.equal(validateEnvironmentName("  Preview  "), "Preview");
});

test("rejects invalid environment identity and recovery configuration", () => {
  for (const operation of [
    () => normalizeEnvironmentSlug("not valid"),
    () => normalizeEnvironmentSlug(""),
    () => validateEnvironmentName("  "),
  ]) {
    assert.throws(
      operation,
      (error: unknown) => error instanceof EnvironmentError && error.code === "INVALID_INPUT",
    );
  }
});
