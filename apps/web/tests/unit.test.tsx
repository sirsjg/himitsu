import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import {
  AppRoutes,
  type CommandItem,
  filterCommandItems,
  validateAuthForm,
} from "../src/App.js";
import {
  SecretConflictError,
  createSecretClient,
  demoSecretRows,
  filterSecretRows,
  isConventionalSecretKey,
  parseBulkSecrets,
} from "../src/SecretWorkspace.js";

function renderRoute(path: string): string {
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
    </MemoryRouter>,
  );
}

test("command search finds navigation, projects, and secret keys using every term", () => {
  const items: readonly CommandItem[] = [
    { id: "audit", label: "Audit log", eyebrow: "Navigate", to: "/app/audit", search: "audit governance navigate" },
    { id: "atlas", label: "Atlas API", eyebrow: "Project", to: "/app/projects/atlas", search: "atlas api project" },
    { id: "database", label: "DATABASE_URL", eyebrow: "Atlas API", to: "/app/projects/atlas?secret=DATABASE_URL", search: "database_url atlas api secret" },
  ];

  assert.deepEqual(filterCommandItems(items, ""), items);
  assert.deepEqual(filterCommandItems(items, "governance").map(({ id }) => id), ["audit"]);
  assert.deepEqual(filterCommandItems(items, "atlas secret").map(({ id }) => id), ["database"]);
  assert.deepEqual(filterCommandItems(items, "missing"), []);
});

test("auth validation rejects malformed credentials and accepts each valid flow", () => {
  assert.equal(validateAuthForm("login", { email: "invalid", password: "correct horse battery staple" }), "Enter a valid email address.");
  assert.equal(validateAuthForm("login", { email: "dev@example.com", password: "short" }), "Password must be at least 12 characters.");
  assert.equal(validateAuthForm("signup", { email: "dev@example.com", password: "long-enough-password", confirmPassword: "different-password" }), "Passwords do not match.");
  assert.equal(validateAuthForm("signup", { email: "dev@example.com", password: "long-enough-password", confirmPassword: "long-enough-password" }), null);
  assert.equal(validateAuthForm("password-reset", { email: "dev@example.com" }), null);
});

test("authenticated project route renders the shell, organization switcher, and project entry points", () => {
  const html = renderRoute("/app/projects");

  assert.match(html, /Himitsu home/);
  assert.match(html, />Projects</);
  assert.match(html, />Audit</);
  assert.match(html, />Settings</);
  assert.match(html, /Active organization/);
  assert.match(html, /Northstar Studio/);
  assert.match(html, /Jump to anything/);
  assert.match(html, /Atlas API/);
  assert.match(html, /Lantern Web/);
  assert.match(html, /Relay Worker/);
});

test("login, signup, and password recovery routes render their complete forms", () => {
  const login = renderRoute("/login");
  assert.match(login, /Enter the vault/);
  assert.match(login, /name="email"/);
  assert.match(login, /name="password"/);
  assert.match(login, /Forgot password/);

  const signup = renderRoute("/signup");
  assert.match(signup, /Start with trust/);
  assert.match(signup, /name="confirmPassword"/);
  assert.match(signup, /Create account/);

  const reset = renderRoute("/password-reset");
  assert.match(reset, /Reset access/);
  assert.doesNotMatch(reset, /name="password"/);
  assert.match(reset, /Send recovery link/);
});

test("invite route renders an actionable acceptance screen", () => {
  const html = renderRoute("/invites/invite-token");

  assert.match(html, /You’re invited/);
  assert.match(html, /Your invitation is ready to accept/);
  assert.match(html, /Accept invitation/);
  assert.match(html, /Use a different account/);
});

test("bulk paste parses dotenv values and reports malformed or duplicate entries", () => {
  const parsed = parseBulkSecrets([
    "# service configuration",
    "DATABASE_URL=postgres://localhost/app",
    'PRIVATE_KEY="first\\nsecond"',
    "legacy.key='literal value'",
    "DATABASE_URL=duplicate",
    "BROKEN_LINE",
  ].join("\n"));

  assert.deepEqual(parsed.secrets, [
    { key: "DATABASE_URL", value: "postgres://localhost/app" },
    { key: "PRIVATE_KEY", value: "first\nsecond" },
    { key: "legacy.key", value: "literal value", allowNonConformingKey: true },
  ]);
  assert.deepEqual(parsed.errors, [
    "Line 5: duplicate key DATABASE_URL",
    "Line 6: expected KEY=value",
  ]);
  assert.equal(isConventionalSecretKey("SENTRY_DSN"), true);
  assert.equal(isConventionalSecretKey("sentry.dsn"), false);
});

test("secret search combines text terms and tag filters without examining values", () => {
  assert.deepEqual(
    filterSecretRows(demoSecretRows, "primary database", "critical").map(({ key }) => key),
    ["DATABASE_URL"],
  );
  assert.deepEqual(
    filterSecretRows(demoSecretRows, "billing", "third-party").map(({ key }) => key),
    ["STRIPE_SECRET_KEY"],
  );
  assert.deepEqual(filterSecretRows(demoSecretRows, "plaintext-not-indexed", null), []);
});

test("secret client targets v1 routes, sends optimistic version preconditions, and surfaces conflicts", async () => {
  const calls: Array<{ input: string; init?: RequestInit }> = [];
  const metadata = {
    id: "secret-id",
    environmentId: "environment-id",
    key: "DATABASE_URL",
    notes: null,
    currentVersion: 4,
    updatedAt: "2026-07-22T00:00:00.000Z",
  };
  const client = createSecretClient(async (input, init) => {
    calls.push({ input, ...(init === undefined ? {} : { init }) });
    return new Response(JSON.stringify({ data: metadata }), { status: 200, headers: { "content-type": "application/json" } });
  });

  await client.update("secret/id", 3, { value: "replacement", changeNote: "rotation" });
  assert.equal(calls[0]?.input, "/api/v1/secrets/secret%2Fid");
  assert.equal(calls[0]?.init?.method, "PATCH");
  assert.equal(new Headers(calls[0]?.init?.headers).get("if-match"), '"3"');
  assert.deepEqual(JSON.parse(String(calls[0]?.init?.body)), { value: "replacement", changeNote: "rotation" });

  const conflicting = createSecretClient(async () => new Response(
    JSON.stringify({ error: { message: "Version is stale" } }),
    { status: 409, headers: { "content-type": "application/json" } },
  ));
  await assert.rejects(() => conflicting.update("secret-id", 2, { value: "replacement" }), (error: unknown) => {
    assert.ok(error instanceof SecretConflictError);
    assert.equal(error.message, "Version is stale");
    return true;
  });

  const importCalls: Array<{ input: string; body: unknown }> = [];
  const imports = createSecretClient(async (input, init) => {
    importCalls.push({ input, body: JSON.parse(String(init?.body)) });
    const data = input.endsWith("/preview")
      ? { entries: [{ key: "A", line: 1, operation: "add" }], conflicts: [], summary: { adds: 1, updates: 0, conflicts: 0 } }
      : { secrets: [], summary: { requested: 1, created: 0, updated: 0, skipped: 1 } };
    return new Response(JSON.stringify({ data }), { status: 200, headers: { "content-type": "application/json" } });
  });
  await imports.previewDotenv("project/id", "environment/id", "A=one");
  await imports.importDotenv("project/id", "environment/id", "A=one", "merge", ["A"]);
  assert.deepEqual(importCalls, [
    { input: "/api/v1/projects/project%2Fid/environments/environment%2Fid/imports/dotenv/preview", body: { content: "A=one" } },
    { input: "/api/v1/projects/project%2Fid/environments/environment%2Fid/imports/dotenv", body: { content: "A=one", strategy: "merge", selectedKeys: ["A"] } },
  ]);
});

test("project detail renders environment browsing and masked secret editing controls", () => {
  const html = renderRoute("/app/projects/project-atlas");

  assert.match(html, /Project vault/);
  assert.match(html, /Development/);
  assert.match(html, /Staging/);
  assert.match(html, /Production/);
  assert.match(html, /Bulk paste/);
  assert.match(html, /Add secret/);
  assert.match(html, /DATABASE_URL/);
  assert.match(html, /Reveal DATABASE_URL/);
  assert.match(html, /#database/);
  assert.match(html, />v7</);
  assert.doesNotMatch(html, /postgres:\/\//);
});
