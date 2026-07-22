import assert from "node:assert/strict";
import { test } from "node:test";
import { SecretError, validateSecretKey, validateSecretValue } from "../src/index.js";

test("validates conventional and explicitly overridden secret keys", () => {
  assert.equal(validateSecretKey(" DATABASE_URL "), "DATABASE_URL");
  assert.equal(validateSecretKey("service.key", true), "service.key");
  assert.throws(
    () => validateSecretKey("service.key"),
    (error: unknown) => error instanceof SecretError && error.code === "KEY_CONVENTION",
  );
  for (const key of ["", "HAS SPACE", "HAS=EQUALS", "LINE\nBREAK"]) {
    assert.throws(
      () => validateSecretKey(key, true),
      (error: unknown) => error instanceof SecretError && error.code === "INVALID_INPUT",
    );
  }
});

test("enforces the UTF-8 value size without rejecting empty values", () => {
  assert.equal(validateSecretValue("").byteLength, 0);
  assert.equal(validateSecretValue("é").byteLength, 2);
  assert.throws(
    () => validateSecretValue("x".repeat(65_537)),
    (error: unknown) => error instanceof SecretError && error.code === "VALUE_TOO_LARGE",
  );
});
