import { expect, test, type Page } from "@playwright/test";
import { installApi } from "./fixtures.js";

async function expectContained(page: Page) {
  const dimensions = await page.evaluate(() => ({ viewport: innerWidth, content: document.documentElement.scrollWidth }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
  // Radix retains hidden native controls for accessibility/form integration.
  for (const select of await page.locator("select").all()) {
    await expect(select).toHaveAttribute("aria-hidden", "true");
    await expect(select).toHaveAttribute("tabindex", "-1");
    await expect(select).toHaveCSS("clip", "rect(0px, 0px, 0px, 0px)");
  }
}

test("custom selects support keyboard navigation, disabled roles, submission, and reset", async ({ page }) => {
  await installApi(page, true);
  await page.goto("/app/settings");
  await expect(page.getByRole("combobox", { name: "Role for owner@example.com" })).toBeDisabled();
  const form = page.getByRole("form", { name: "Create API key" });
  const access = form.getByRole("combobox", { name: "Access", exact: true });
  await access.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("listbox")).toBeVisible();
  await expect(page.getByRole("option", { name: "Read-only", exact: true })).toBeFocused();
  await page.keyboard.press("End");
  await expect(page.getByRole("option", { name: "Read-write", exact: true })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(access).toContainText("Read-write");
  await expect(access).toBeFocused();
  await access.press("Space");
  await page.keyboard.press("Escape");
  await expect(access).toBeFocused();
  await expect(page.getByRole("listbox")).toHaveCount(0);

  await form.getByRole("combobox", { name: "Scope", exact: true }).click();
  await page.getByRole("option", { name: "Project + environment", exact: true }).click();
  await form.getByRole("combobox", { name: "Project", exact: true }).click();
  await page.getByRole("option", { name: "Payments API", exact: true }).click();
  await expect(form.getByRole("combobox", { name: "Environment", exact: true })).toContainText("Development");
  await form.getByRole("combobox", { name: "Environment", exact: true }).click();
  await page.getByRole("option", { name: "Staging", exact: true }).click();
  await form.getByLabel("Name", { exact: true }).fill("Scoped deploy");
  const request = page.waitForRequest((request) => request.url().endsWith("/api-keys") && request.method() === "POST");
  await form.getByRole("button", { name: "Create key" }).click();
  expect((await request).postDataJSON()).toEqual({ name: "Scoped deploy", access: "read_write", projectId: "e2e-project", environmentId: "staging", expiresAt: null });
  await expect(access).toContainText("Read-only");
  await expectContained(page);
});

test("audit dropdown supports typeahead and clearing the action filter", async ({ page }) => {
  await installApi(page);
  await page.goto("/app/audit");
  const action = page.getByRole("combobox", { name: "Action", exact: true });
  await action.click();
  await expect(page.getByRole("option", { name: "secret.updated", exact: true })).toBeVisible();
  await expect(page.getByRole("option", { name: "All actions", exact: true })).toBeFocused();
  await page.keyboard.type("secret.updated", { delay: 30 });
  await expect(page.getByRole("option", { name: "secret.updated", exact: true })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(action).toContainText("secret.updated");
  await action.click();
  await page.getByRole("option", { name: "All actions", exact: true }).click();
  await expect(action).toContainText("All actions");
  const request = page.waitForRequest((request) => request.url().includes("/audit-events"));
  await page.getByRole("button", { name: "Apply filters" }).click();
  expect(new URL((await request).url()).searchParams.has("action")).toBe(false);
});

for (const width of [320, 390, 768, 1024, 1440]) {
  test(`workspace layouts and dropdowns fit at ${width}px in both themes`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await installApi(page, true);
    for (const theme of ["dark", "light"]) {
      for (const route of ["projects", "projects/e2e-project", "audit", "settings"]) {
        await page.goto(`/app/${route}`);
        await page.evaluate((theme) => document.documentElement.dataset.theme = theme, theme);
        await expect(page.getByRole("main").getByRole("heading", { level: 1 })).toBeVisible();
        await expectContained(page);
        await page.getByRole("combobox", { name: "Active organization" }).click();
        const bounds = await page.getByRole("listbox").boundingBox();
        expect(bounds).not.toBeNull();
        expect(bounds!.x).toBeGreaterThanOrEqual(0);
        expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
        await page.keyboard.press("Escape");
      }
    }
  });
}
