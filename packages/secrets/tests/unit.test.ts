import assert from "node:assert/strict";
import { test } from "node:test";
import { SecretError, serializeSecretExport, validateSecretKey, validateSecretValue } from "../src/index.js";

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

test("serializes stable dotenv, flat or nested JSON, and safely quoted shell exports", () => {
  const values = { ZED: "line\nvalue", "DATABASE__HOST": "db.internal", QUOTE: "it's safe" };
  assert.equal(
    serializeSecretExport(values, "dotenv"),
    'DATABASE__HOST="db.internal"\nQUOTE="it\'s safe"\nZED="line\\nvalue"\n',
  );
  assert.equal(
    serializeSecretExport(values, "json", { nested: true }),
    '{\n  "DATABASE": {\n    "HOST": "db.internal"\n  },\n  "QUOTE": "it\'s safe",\n  "ZED": "line\\nvalue"\n}\n',
  );
  assert.equal(
    serializeSecretExport({ TOKEN: "one'two" }, "shell"),
    "export TOKEN='one'\\''two'\n",
  );
  assert.throws(
    () => serializeSecretExport({ A: "one", A__B: "two" }, "json", { nested: true }),
    (error: unknown) => error instanceof SecretError && error.code === "INVALID_INPUT",
  );
  assert.throws(
    () => serializeSecretExport({ "invalid-key": "value" }, "shell"),
    (error: unknown) => error instanceof SecretError && error.code === "INVALID_INPUT",
  );
});
