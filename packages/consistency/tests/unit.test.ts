import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeConsistency } from "../src/index.js";

test("detects missing, empty, placeholder, naming, and case drift without retaining values", () => {
  const findings = analyzeConsistency(
    "project-1",
    [{ id: "dev", slug: "development" }, { id: "prod", slug: "production" }],
    [
      { secretId: "1", environmentId: "dev", key: "DATABASE_URL", value: "postgres://private" },
      { secretId: "2", environmentId: "prod", key: "database_url", value: "postgres://other" },
      { secretId: "3", environmentId: "dev", key: "EMPTY_VALUE", value: "" },
      { secretId: "4", environmentId: "dev", key: "PLACEHOLDER", value: "changeme" },
      { secretId: "5", environmentId: "dev", key: "ONLY_DEV", value: "real" },
    ],
  );
  assert.deepEqual(new Set(findings.map(({ type }) => type)), new Set([
    "missing_key", "empty_value", "placeholder_value", "naming_violation", "case_duplicate",
  ]));
  assert.equal(findings.find(({ type, key }) => type === "missing_key" && key === "ONLY_DEV")?.severity, "error");
  assert.deepEqual(
    findings.find(({ type }) => type === "case_duplicate")?.keys,
    ["DATABASE_URL", "database_url"],
  );
  const encoded = JSON.stringify(findings);
  assert.doesNotMatch(encoded, /postgres:\/\/|changeme/);
  assert.equal(findings.every(({ id }) => /^[0-9a-f]{64}$/.test(id)), true);
});

test("does not report missing keys when a project has one environment and no secrets", () => {
  assert.deepEqual(analyzeConsistency("project-2", [{ id: "dev", slug: "development" }], []), []);
});
