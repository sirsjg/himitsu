import { type Page, type Route } from "@playwright/test";

const now = "2026-07-22T10:00:00.000Z";

async function json(route: Route, data: unknown, status = 200): Promise<void> {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify({ data }) });
}

export async function installApi(page: Page, populated = false): Promise<void> {
  const keys = new Set<string>(populated ? ["DATABASE_URL", "REDIS_URL", "SENTRY_DSN"] : []);
  const createdProjects: Array<Record<string, unknown>> = populated ? [
    { id: "e2e-project", name: "Payments API", slug: "payments-api", settings: { defaultEnvironments: ["development", "staging", "production"] }, tags: [{ name: "platform" }] },
    { id: "web-project", name: "Customer portal", slug: "customer-portal", settings: { defaultEnvironments: ["development", "staging", "production"] }, tags: [{ name: "customer" }] },
    { id: "long-project", name: "International payment processing", slug: "international-payment-processing", settings: { defaultEnvironments: ["development", "staging", "production"] }, tags: [] },
  ] : [];
  const serviceKeys: Array<Record<string, unknown>> = [];
  const environments: Array<{ id: string; name: string; slug: string; displayOrder: number; protected: boolean }> = [
    { id: "development", name: "Development", slug: "development", displayOrder: 0, protected: false },
    { id: "staging", name: "Staging", slug: "staging", displayOrder: 1, protected: false },
    { id: "production", name: "Production", slug: "production", displayOrder: 2, protected: true },
  ];
  const environmentRow = (row: typeof environments[number]) => ({ ...row, orgId: "org-studio", projectId: "e2e-project", deletedAt: null, purgeAfter: null });
  let nextSecret = 1;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/auth/login") return json(route, {});
    if (path === "/api/v1/session") {
      return json(route, {
        user: { id: "e2e-user", email: "owner@example.com" },
        organizations: [{ id: "org-studio", name: "Northstar Studio", slug: "northstar-studio", role: "owner", active: true }],
        activeOrgId: "org-studio",
        expiresAt: "2099-01-01T00:00:00.000Z",
      });
    }
    if (path === "/api/v1/projects" && request.method() === "GET") {
      return json(route, createdProjects.map((project) => project.id === "e2e-project" ? { ...project, environments: environments.map(environmentRow) } : project));
    }
    if (path.endsWith("/environments") && request.method() === "GET") return json(route, environments.map(environmentRow));
    if (path.endsWith("/environments") && request.method() === "POST") {
      const body = request.postDataJSON() as { name: string; slug: string; protected?: boolean };
      if (environments.some(({ slug }) => slug === body.slug)) {
        return route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ error: { code: "SLUG_EXISTS", message: "Environment slug is already in use in this project" } }) });
      }
      const created = { id: body.slug, name: body.name, slug: body.slug, displayOrder: environments.length, protected: body.protected ?? false };
      environments.push(created);
      return json(route, environmentRow(created), 201);
    }
    if (path.endsWith("/environments/reorder") && request.method() === "POST") {
      const { environmentIds } = request.postDataJSON() as { environmentIds: string[] };
      environments.sort((left, right) => environmentIds.indexOf(left.id) - environmentIds.indexOf(right.id));
      environments.forEach((row, index) => { row.displayOrder = index; });
      return json(route, environments.map(environmentRow));
    }
    const environmentMatch = /\/environments\/([^/]+)$/.exec(path);
    const targetEnvironment = environmentMatch === null ? undefined : environments.find(({ id }) => id === environmentMatch[1]);
    if (targetEnvironment !== undefined && request.method() === "PATCH") {
      Object.assign(targetEnvironment, request.postDataJSON() as Partial<typeof targetEnvironment>);
      return json(route, environmentRow(targetEnvironment));
    }
    if (targetEnvironment !== undefined && request.method() === "DELETE") {
      const holdsSecrets = targetEnvironment.id === "development" && keys.size > 0;
      if (holdsSecrets && new URL(request.url()).searchParams.get("confirmSecrets") !== "true") {
        return route.fulfill({ status: 400, contentType: "application/json", body: JSON.stringify({ error: { code: "SECRETS_REQUIRE_CONFIRMATION", message: "Confirm deletion because this environment contains active secrets" } }) });
      }
      environments.splice(environments.indexOf(targetEnvironment), 1);
      return json(route, environmentRow(targetEnvironment));
    }
    if (path.endsWith("/secrets") && request.method() === "GET") {
      return json(route, [...keys].sort().map((key, index) => ({ id: `secret-${index + 1}`, orgId: "org-studio", projectId: "e2e-project", environmentId: "development", key, notes: null, currentVersion: 1, updatedAt: now, tagIds: [], tags: [] })));
    }
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
      const project = { id: "e2e-project", orgId: "org-studio", name: "E2E Vault", slug: "e2e-vault", description: null, settings: { defaultEnvironments: ["development", "staging", "production"] }, tagIds: [], tags: [], archivedAt: null, deletedAt: null, purgeAfter: null };
      createdProjects.push(project);
      return json(route, { ...project, environments: environments.map(environmentRow) }, 201);
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

