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
