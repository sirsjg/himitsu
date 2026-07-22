import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildDotenvPreview,
  buildJsonImportPreview,
  parseDotenv,
  parseJsonSecrets,
} from "../src/index.js";

test("parses comments, export assignments, empty values, and unquoted inline comments", () => {
  const result = parseDotenv([
    "# application settings",
    "export DATABASE_URL = postgres://localhost/app # local only",
    "EMPTY=",
    "HASH=escaped\\#fragment",
    "DOTTED.KEY=value",
  ].join("\n"));

  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.entries, [
    { key: "DATABASE_URL", value: "postgres://localhost/app", line: 2 },
    { key: "EMPTY", value: "", line: 3 },
    { key: "HASH", value: "escaped#fragment", line: 4 },
    { key: "DOTTED.KEY", value: "value", line: 5 },
  ]);
});

test("parses single, double, and backtick quotes with escapes and multiline content", () => {
  const result = parseDotenv([
    "DOUBLE=\"line one\\nline two\\t\\\"quoted\\\"\" # note",
    "SINGLE='literal \\n text'",
    "MULTILINE=`first",
    "second`",
  ].join("\n"));

  assert.deepEqual(result.issues, []);
  assert.equal(result.entries[0]?.value, 'line one\nline two\t"quoted"');
  assert.equal(result.entries[1]?.value, String.raw`literal \n text`);
  assert.equal(result.entries[2]?.value, "first\nsecond");
});

test("reports malformed assignments, invalid and duplicate keys, unterminated quotes, and trailing content", () => {
  const result = parseDotenv("\uFEFFGOOD=one\r\nBAD LINE\r\n1INVALID=x\r\nGOOD=two\r\nBROKEN=\"open\r\nvalue");

  assert.deepEqual(result.entries, [{ key: "GOOD", value: "one", line: 1 }]);
  assert.deepEqual(result.issues.map(({ code }) => code), [
    "INVALID_ASSIGNMENT",
    "INVALID_KEY",
    "DUPLICATE_KEY",
    "UNTERMINATED_QUOTE",
  ]);
  const trailing = parseDotenv('KEY="value" unexpected');
  assert.equal(trailing.issues[0]?.code, "TRAILING_CONTENT");
});

test("builds a value-free add/update/conflict preview", () => {
  const parsed = parseDotenv("NEW_KEY=new-sensitive-value\nEXISTING_KEY=updated-sensitive-value\nINVALID");
  const preview = buildDotenvPreview(parsed, new Set(["EXISTING_KEY"]));

  assert.deepEqual(preview.entries, [
    { key: "NEW_KEY", line: 1, operation: "add" },
    { key: "EXISTING_KEY", line: 2, operation: "update" },
  ]);
  assert.deepEqual(preview.summary, { adds: 1, updates: 1, conflicts: 1 });
  assert.doesNotMatch(JSON.stringify(preview), /sensitive-value/);
});

test("flattens nested JSON with a configurable delimiter and stable primitive conversion", () => {
  const parsed = parseJsonSecrets(JSON.stringify({
    DATABASE: { HOST: "db.internal", PORT: 5432, TLS: true },
    EMPTY: "",
  }), "__");

  assert.deepEqual(parsed.issues, []);
  assert.deepEqual(parsed.entries, [
    { key: "DATABASE__HOST", value: "db.internal", path: "$.DATABASE.HOST" },
    { key: "DATABASE__PORT", value: "5432", path: "$.DATABASE.PORT" },
    { key: "DATABASE__TLS", value: "true", path: "$.DATABASE.TLS" },
    { key: "EMPTY", value: "", path: "$.EMPTY" },
  ]);
  assert.deepEqual(parseJsonSecrets('{"A":{"B":false}}', ".").entries, [
    { key: "A.B", value: "false", path: "$.A.B" },
  ]);
});

test("reports JSON syntax, root, array, null, delimiter, key, and flattened collision errors", () => {
  assert.equal(parseJsonSecrets("{").issues[0]?.code, "INVALID_JSON");
  assert.equal(parseJsonSecrets("[]").issues[0]?.code, "ROOT_NOT_OBJECT");
  assert.equal(parseJsonSecrets('{"A":[1,2]}').issues[0]?.code, "ARRAY_NOT_SUPPORTED");
  assert.equal(parseJsonSecrets('{"A":null}').issues[0]?.code, "UNSUPPORTED_TYPE");
  assert.equal(parseJsonSecrets('{"A":1}', " ").issues[0]?.code, "INVALID_DELIMITER");
  assert.equal(parseJsonSecrets('{"bad key":1}').issues[0]?.code, "INVALID_KEY");
  const collision = parseJsonSecrets('{"A__B":"flat","A":{"B":"nested"}}');
  assert.equal(collision.issues[0]?.code, "KEY_COLLISION");
});

test("builds a value-free JSON add/update/conflict preview", () => {
  const parsed = parseJsonSecrets('{"NEW":"new-sensitive","NESTED":{"OLD":"updated-sensitive"},"BAD":[]}');
  const preview = buildJsonImportPreview(parsed, new Set(["NESTED__OLD"]));

  assert.deepEqual(preview.entries, [
    { key: "NEW", path: "$.NEW", operation: "add" },
    { key: "NESTED__OLD", path: "$.NESTED.OLD", operation: "update" },
  ]);
  assert.deepEqual(preview.summary, { adds: 1, updates: 1, conflicts: 1 });
  assert.doesNotMatch(JSON.stringify(preview), /sensitive/);
});
