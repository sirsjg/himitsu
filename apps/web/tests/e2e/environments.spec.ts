import { expect, test } from "@playwright/test";
import { installApi } from "./fixtures.js";

test("environments can be added, reordered, renamed, protected, and deleted from the workspace", async ({ page }) => {
  await installApi(page, true);
  await page.goto("/login");
  await page.getByLabel("Work email").fill("owner@example.com");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.goto("/app/projects/e2e-project");

  const tabs = page.getByRole("navigation", { name: "Project environments" });
  await expect(tabs.getByRole("button")).toHaveText([/Development/, /Staging/, /Production/, /Manage/]);

  await tabs.getByRole("button", { name: "Manage" }).click();
  const manager = page.getByRole("dialog", { name: "Manage environments" });
  const list = manager.getByRole("list", { name: "Environments in display order" });
  await expect(list.getByRole("listitem")).toHaveCount(3);

  // Add: the slug follows the name until edited, and the new tab appears last.
  const creator = manager.getByRole("form", { name: "Add environment" });
  await creator.getByLabel("Name").fill("QA Load");
  await expect(creator.getByLabel("Slug")).toHaveValue("qa-load");
  await creator.getByRole("button", { name: "Add environment" }).click();
  await expect(manager.getByRole("status")).toHaveText("QA Load added.");
  await expect(list.getByRole("listitem")).toHaveCount(4);
  await expect(tabs.getByRole("button")).toHaveText([/Development/, /Staging/, /Production/, /QA Load/, /Manage/]);

  // Reorder: moving QA Load up twice places it after Development.
  await manager.getByRole("button", { name: "Move QA Load up" }).click();
  await expect(manager.getByRole("status")).toHaveText("Environment order saved.");
  await manager.getByRole("button", { name: "Move QA Load up" }).click();
  await expect(tabs.getByRole("button")).toHaveText([/Development/, /QA Load/, /Staging/, /Production/, /Manage/]);
  await expect(manager.getByRole("button", { name: "Move Development up" })).toBeDisabled();

  // Rename and protect.
  await manager.getByRole("button", { name: "Edit QA Load" }).click();
  const editor = manager.getByRole("form", { name: "Edit QA Load" });
  await editor.getByLabel("Name").fill("Quality");
  await editor.getByLabel("Slug").fill("quality");
  await editor.getByLabel("Protected").check();
  await editor.getByRole("button", { name: "Save" }).click();
  await expect(manager.getByRole("status")).toHaveText("Quality updated.");
  await expect(tabs.getByRole("button", { name: /Quality/ })).toContainText("◆");

  // Duplicate slugs surface the API message without closing the manager.
  await creator.getByLabel("Name").fill("Staging");
  await creator.getByRole("button", { name: "Add environment" }).click();
  await expect(manager.getByRole("alert")).toContainText("already in use");

  // Delete an empty environment with inline confirmation.
  await manager.getByRole("button", { name: "Delete Quality" }).click();
  await expect(manager.getByRole("alert")).toContainText("Delete Quality?");
  await manager.getByRole("button", { name: "Delete environment" }).click();
  await expect(manager.getByRole("status")).toHaveText("Quality deleted.");
  await expect(tabs.getByRole("button")).toHaveText([/Development/, /Staging/, /Production/, /Manage/]);

  // Deleting the environment that holds secrets requires a second, explicit confirmation.
  await manager.getByRole("button", { name: "Delete Development" }).click();
  await expect(manager.getByRole("alert")).toContainText("3 secrets will be deleted with it");
  await manager.getByRole("button", { name: "Delete environment" }).click();
  await expect(manager.getByRole("status")).toHaveText("Development deleted with 3 secrets.");
  await manager.getByRole("button", { name: "Done" }).click();
  await expect(manager).toBeHidden();
  await expect(tabs.getByRole("button")).toHaveText([/Staging/, /Production/, /Manage/]);
  await expect(tabs.getByRole("button", { name: /Staging/ })).toHaveClass(/active/);

  // The project card reflects the live list without a reload.
  await page.getByRole("link", { name: "Projects", exact: true }).first().click();
  const card = page.getByRole("link", { name: /Payments API/ });
  await expect(card).toContainText("2 environments");
  await expect(card.locator(".environment-row span")).toHaveText(["STA", "PRO"]);
});
