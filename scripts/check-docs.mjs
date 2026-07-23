import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildApi } from "../apps/api/dist/src/index.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requiredSections = new Map([
  ["docs/getting-started.md", ["Create the organization", "Create the first project", "Import an existing `.env`", "Connect CI", "Connect an application runtime"]],
  ["docs/api-reference.md", ["OpenAPI 3.1", "Authentication", "Resource groups", "OpenAPI workflow"]],
  ["docs/cli.md", ["Repository configuration", "Authentication", "Pull and export", "Push and import", "Run a process without a file", "Consistency check", "Individual secret operations", "Exit codes"]],
  ["docs/self-hosting.md", ["First deployment", "Health, logs, and metrics", "Encrypted backup procedure", "Restore runbook", "Releases"]],
]);

for (const [path, sections] of requiredSections) {
  const content = await readFile(resolve(root, path), "utf8");
  for (const section of sections) assert.ok(content.includes(section), `${path} is missing ${section}`);
  assert.doesNotMatch(content, /\b(?:TODO|TBD)\b/, `${path} contains an unfinished placeholder`);
}

const linkedDocuments = ["README.md", ...requiredSections.keys()];
for (const path of linkedDocuments) {
  const content = await readFile(resolve(root, path), "utf8");
  for (const match of content.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    const target = match[1];
    if (target === undefined || /^(?:https?:|#)/.test(target)) continue;
    const localPath = target.split("#", 1)[0];
    if (!localPath) continue;
    await access(resolve(dirname(resolve(root, path)), localPath));
  }
}

const cli = await readFile(resolve(root, "docs/cli.md"), "utf8");
for (const command of ["config set", "login", "pull", "push", "run", "check", "secrets set", "secrets get", "secrets rm"]) {
  assert.ok(cli.includes(command), `CLI reference is missing ${command}`);
}

const app = await buildApi({});
try {
  const expected = `${JSON.stringify(app.swagger(), null, 2)}\n`;
  const actual = await readFile(resolve(root, "docs/openapi.json"), "utf8");
  assert.equal(actual, expected, "docs/openapi.json is stale; run npm run docs:openapi after building the API");
  const document = JSON.parse(actual);
  assert.equal(document.openapi, "3.1.0");
  for (const path of [
    "/api/v1/organization",
    "/api/v1/projects",
    "/api/v1/projects/{projectId}/environments/{environmentId}/secrets/runtime",
    "/api/v1/projects/{projectId}/environments/{environmentId}/exports",
    "/api/v1/api-keys",
    "/api/v1/audit-events",
  ]) assert.ok(document.paths[path], `OpenAPI document is missing ${path}`);
  const operationIds = Object.values(document.paths).flatMap((methods) => Object.values(methods).map(({ operationId }) => operationId).filter(Boolean));
  assert.equal(new Set(operationIds).size, operationIds.length, "OpenAPI operation IDs must be unique");
} finally {
  await app.close();
}

process.stdout.write("Documentation, links, CLI coverage, and generated OpenAPI contract are current.\n");
