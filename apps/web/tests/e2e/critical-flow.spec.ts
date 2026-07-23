import { expect, test, type Page, type Route } from "@playwright/test";

const now = "2026-07-22T10:00:00.000Z";

async function json(route: Route, data: unknown, status = 200): Promise<void> {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify({ data }) });
}

async function installApi(page: Page): Promise<void> {
  const keys = new Set<string>();
  const serviceKeys: Array<Record<string, unknown>> = [];
  let nextSecret = 1;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/auth/login") return json(route, {});
    if (path === "/api/v1/organization") return json(route, { id: "org-studio", name: "Northstar Studio", slug: "northstar-studio", retentionDays: 90, createdAt: now, updatedAt: now });
    if (path === "/api/v1/members") return json(route, [{ userId: "e2e-user", email: "owner@example.com", role: "owner", status: "active", createdAt: now, updatedAt: now }]);
    if (path === "/api/v1/invitations") return json(route, []);
    if (path === "/api/v1/api-keys" && request.method() === "GET") return json(route, serviceKeys);
    if (path === "/api/v1/api-keys" && request.method() === "POST") {
      const body = request.postDataJSON() as { name: string; access: string };
      const apiKey = { id: "e2e-key", projectId: null, environmentId: null, name: body.name, prefix: "himi_0123456789abcdef", access: body.access, createdAt: now, expiresAt: null, lastUsedAt: null, revokedAt: null };
      serviceKeys.push(apiKey);
      return json(route, { apiKey, token: "himi_0123456789abcdef_abcdefghijklmnopqrstuvwxyzABCDEFGH123456789" }, 201);
    }
    if (path === "/api/v1/projects" && request.method() === "POST") {
      return json(route, { id: "e2e-project", name: "E2E Vault", slug: "e2e-vault", tags: [] }, 201);
    }
    if (path === "/api/v1/tags" && request.method() === "GET") return json(route, []);
    if (path.endsWith("/consistency")) {
      const matrix = [...keys].sort().map((key) => ({
        key,
        keys: [key],
        cells: [
          { environmentId: "development", state: "present", secretId: `secret-${key}` },
          { environmentId: "staging", state: "missing", secretId: null },
          { environmentId: "production", state: "missing", secretId: null },
        ],
      }));
      return json(route, {
        computedAt: now,
        cached: false,
        environments: ["development", "staging", "production"].map((id) => ({ id, slug: id })),
        matrix,
        findings: matrix.map(({ key }) => ({ id: `missing-${key}`, type: "missing_key", severity: "error", key, keys: [key], environmentIds: ["development"], missingEnvironmentIds: ["staging", "production"], disposition: null })),
        summary: { healthy: matrix.length === 0, exitCode: matrix.length === 0 ? 0 : 1, totalFindings: matrix.length, activeFindings: matrix.length, errors: matrix.length, warnings: 0 },
      });
    }
    if (path.endsWith("/promotions/preview")) {
      const targetEnvironmentId = path.split("/").at(-3) ?? "staging";
      const items = [...keys].sort().map((key) => ({ key, action: "create", changed: true, sourceVersion: 1, targetVersion: null }));
      return json(route, { sourceEnvironmentId: "development", targetEnvironmentId, items, summary: { selected: items.length, created: items.length, overwritten: 0 } });
    }
    if (path.endsWith("/secrets") && request.method() === "POST") {
      const body = request.postDataJSON() as { key: string };
      keys.add(body.key);
      return json(route, { id: `secret-${nextSecret++}`, environmentId: "development", key: body.key, notes: null, currentVersion: 1, updatedAt: now, tagIds: [], tags: [] }, 201);
    }
    if (path.endsWith("/imports/dotenv/preview")) {
      return json(route, {
        entries: [
          { key: "REDIS_URL", line: 1, operation: "add" },
          { key: "SENTRY_DSN", line: 2, operation: "add" },
        ],
        conflicts: [],
        summary: { adds: 2, updates: 0, conflicts: 0 },
      });
    }
    if (path.endsWith("/imports/dotenv")) {
      keys.add("REDIS_URL");
      keys.add("SENTRY_DSN");
      return json(route, {
        secrets: ["REDIS_URL", "SENTRY_DSN"].map((key) => ({ id: `secret-${nextSecret++}`, environmentId: "development", key, notes: null, currentVersion: 1, updatedAt: now, tagIds: [], tags: [] })),
        summary: { created: 2, updated: 0, skipped: 0 },
      });
    }
    if (path === "/api/v1/audit-settings") return json(route, { retentionDays: 90 });
    if (path === "/api/v1/audit-events") {
      return json(route, {
        events: [{ id: "audit-1", actor: { type: "user", id: "e2e-user", label: "owner@example.com" }, action: "secret.imported", resource: { type: "environment", id: "development" }, projectId: "e2e-project", environmentId: "development", ip: "127.0.0.1", userAgent: "Playwright", metadata: { details: { requested: 2 } }, occurredAt: now }],
        nextCursor: null,
      });
    }
    return route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: { message: `Unhandled E2E route: ${request.method()} ${path}` } }) });
  });
}

test("login, project creation, secret writes, dotenv import, diff, audit, and settings", async ({ page }) => {
  await installApi(page);
  await page.goto("/login");
  await page.getByLabel("Work email").fill("owner@example.com");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/app\/projects$/);

  await page.getByRole("button", { name: "New project" }).click();
  await page.getByRole("form", { name: "Create project" }).getByLabel("Name").fill("E2E Vault");
  await page.getByRole("form", { name: "Create project" }).getByLabel("Slug").fill("e2e-vault");
  await page.getByRole("button", { name: "Create project", exact: true }).click();
  await expect(page).toHaveURL(/\/app\/projects\/e2e-project$/);
  await expect(page.getByRole("heading", { name: "E2E Vault" })).toBeVisible();

  await page.getByRole("button", { name: "Add secret" }).click();
  const editor = page.getByRole("form", { name: "Add secret" });
  await editor.getByLabel("Key").fill("DATABASE_URL");
  await editor.getByLabel("Value").fill("postgres://db/app");
  await editor.getByRole("button", { name: "Encrypt & save" }).click();
  await expect(page.getByText("DATABASE_URL", { exact: true }).first()).toBeVisible();

  await page.getByRole("button", { name: "Bulk paste" }).click();
  const importer = page.getByRole("dialog", { name: "Import secrets" });
  await importer.getByLabel("Paste dotenv content").fill("REDIS_URL=redis://cache\nSENTRY_DSN=https://example@sentry.invalid/1");
  await importer.getByRole("button", { name: "Preview import" }).click();
  const commitImport = importer.getByRole("button", { name: "Commit 2 keys" });
  await expect(commitImport).toBeEnabled();
  await commitImport.click();
  await expect(page.getByRole("status")).toContainText("Import complete: 2 added");

  await expect(page.getByRole("table", { name: "Key by environment consistency matrix" })).toContainText("SENTRY_DSN");
  await expect(page.getByText("needs copy").first()).toBeVisible();
  await page.getByRole("link", { name: "Audit" }).click();
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();
  await expect(page.locator("code").filter({ hasText: "secret.imported" })).toBeVisible();
  await expect(page.getByText("owner@example.com")).toBeVisible();

  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Members & invitations" })).toBeVisible();
  await expect(page.getByText("owner@example.com")).toBeVisible();
  const keyForm = page.getByRole("form", { name: "Create API key" });
  await keyForm.getByLabel("Name").fill("E2E deploy");
  await keyForm.getByRole("button", { name: "Create key" }).click();
  await expect(page.getByRole("alert")).toContainText("Copy E2E deploy now");
  await expect(page.getByRole("alert").locator("code")).toContainText("himi_0123456789abcdef_");
  await expect(page.getByRole("heading", { name: "Import & export" })).toBeVisible();
});
