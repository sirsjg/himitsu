import assert from "node:assert/strict";
import { test } from "node:test";
import { TenancyError, normalizeOrganizationSlug } from "../src/index.js";

test("normalizes valid organization slugs", () => {
  assert.equal(normalizeOrganizationSlug("  Acme-Platform  "), "acme-platform");
});

test("rejects unsafe organization slugs", () => {
  for (const slug of ["", "two words", "UPPER_case", "-leading", "trailing-", "a".repeat(81)]) {
    assert.throws(
      () => normalizeOrganizationSlug(slug),
      (error: unknown) => error instanceof TenancyError && error.code === "INVALID_INPUT",
    );
  }
});
