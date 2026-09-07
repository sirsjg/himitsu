import { expect, test } from "@playwright/test";
import { installApi } from "./fixtures.js";

test("login, project creation, secret writes, dotenv import, diff, audit, and settings", async ({ page }) => {
  await installApi(page);
  await page.goto("/login");
  await page.getByLabel("Work email").fill("owner@example.com");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/app\/projects$/);

  await page.getByRole("button", { name: "Collapse sidebar" }).click();
  await expect(page.locator(".app-frame")).toHaveClass(/sidebar-collapsed/);
  await page.reload();
  await expect(page.locator(".app-frame")).toHaveClass(/sidebar-collapsed/);
  await page.getByRole("button", { name: "Expand sidebar" }).click();
  await expect(page.locator(".app-frame")).not.toHaveClass(/sidebar-collapsed/);

  await page.getByRole("button", { name: "New project" }).click();
  const projectForm = page.getByRole("form", { name: "Create project" });
  await projectForm.getByLabel("Name").fill("E2E Vault");
  await expect(projectForm.getByLabel("Slug")).toHaveValue("e2e-vault");
  await page.getByRole("button", { name: "Create project", exact: true }).click();
  await expect(page).toHaveURL(/\/app\/projects\/e2e-project$/);
  await expect(page.getByRole("heading", { name: "E2E Vault" })).toBeVisible();

  // Moved from tests/unit.test.tsx: environment browsing and the empty-vault
  // state render behind the environments fetch, which renderToStaticMarkup can
  // never resolve because it does not run effects.
  await expect(page.getByText("Project vault")).toBeVisible();
  const environmentTabs = page.getByRole("navigation", { name: "Project environments" });
  for (const environment of ["Development", "Staging", "Production"]) {
    await expect(environmentTabs.getByRole("button", { name: new RegExp(environment) })).toBeVisible();
  }
  await expect(page.getByText("This environment is ready for its first secret")).toBeVisible();
  await expect(page.getByRole("button", { name: "Add first secret" })).toBeVisible();

  await page.getByRole("button", { name: "Add secret" }).click();
  const editor = page.getByRole("form", { name: "Add secret" });
  await editor.getByLabel("Key").fill("DATABASE_URL");
  await editor.getByLabel("Value").fill("postgres://db/app");
  await editor.getByRole("button", { name: "Encrypt & save" }).click();
  await expect(page.getByText("DATABASE_URL", { exact: true }).first()).toBeVisible();
  // The plaintext must never reach the document until explicitly revealed.
  await expect(page.locator("body")).not.toContainText("postgres://db/app");

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
  await expect(page.getByLabel("Audit events").getByText("owner@example.com")).toBeVisible();

  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Members & invitations" })).toBeVisible();
  await expect(page.getByRole("main").getByText("owner@example.com").first()).toBeVisible();
  const keyForm = page.getByRole("form", { name: "Create API key" });
  await keyForm.getByLabel("Name").fill("E2E deploy");
  await keyForm.getByRole("button", { name: "Create key" }).click();
  await expect(page.getByRole("alert")).toContainText("Copy E2E deploy now");
  await expect(page.getByRole("alert").locator("code")).toContainText("himi_0123456789abcdef_");
  await expect(page.getByRole("heading", { name: "Import & export" })).toBeVisible();
});
