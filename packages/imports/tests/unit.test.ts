import assert from "node:assert/strict";
import { test } from "node:test";
import { buildDotenvPreview, parseDotenv } from "../src/index.js";

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
