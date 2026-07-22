import swagger from "@fastify/swagger";
import { AuthorizationContextResolver, AuthorizationError, requirePermission } from "@himitsu/authz";
import { EnvironmentError, type EnvironmentService } from "@himitsu/environments";
import { ProjectError, type ProjectService } from "@himitsu/projects";
import { SecretError, type SecretService } from "@himitsu/secrets";
import { TenancyError, type TenantDatabase, type TenantTransaction } from "@himitsu/tenancy";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";

export interface ApiRequestContext {
  readonly orgId: string;
  readonly userId: string;
}

export interface ApiDependencies {
  readonly database: TenantDatabase;
  readonly projects: ProjectService;
  readonly environments: EnvironmentService;
  readonly secrets: SecretService;
  readonly resolveRequestContext: (request: FastifyRequest) => Promise<ApiRequestContext> | ApiRequestContext;
}

export class ApiError extends Error {
  readonly code: string;
  readonly statusCode: number;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(
    statusCode: number,
    code: string,
    message: string,
    details?: Readonly<Record<string, unknown>>,
  ) {
    super(message);
    this.name = "ApiError";
    this.statusCode = statusCode;
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

interface IdParams {
  projectId?: string;
  environmentId?: string;
  secretId?: string;
  tagId?: string;
}

interface PageQuery {
  limit?: number;
  offset?: number;
}

interface TagRow {
  id: string;
  name: string;
  color: string;
  created_at: Date;
  updated_at: Date;
}

const uuid = { type: "string", format: "uuid" } as const;
const idParams = (properties: Record<string, unknown>) => ({
  type: "object",
  additionalProperties: false,
  required: Object.keys(properties),
  properties,
});
const pageQuery = {
  type: "object",
  additionalProperties: false,
  properties: {
    limit: { type: "integer", minimum: 1, maximum: 100, default: 50 },
    offset: { type: "integer", minimum: 0, default: 0 },
  },
} as const;
const errorResponse = {
  type: "object",
  additionalProperties: false,
  required: ["error"],
  properties: {
    error: {
      type: "object",
      additionalProperties: false,
      required: ["code", "message", "requestId"],
      properties: {
        code: { type: "string" },
        message: { type: "string" },
        requestId: { type: "string" },
        details: { type: "object", additionalProperties: true },
      },
    },
  },
} as const;
const dateTime = { type: "string", format: "date-time" } as const;
const nullableDateTime = { type: ["string", "null"], format: "date-time" } as const;
const projectSchema = {
  type: "object", additionalProperties: false,
  required: ["id", "orgId", "name", "slug", "description", "settings", "tagIds", "archivedAt", "deletedAt", "purgeAfter"],
  properties: {
    id: uuid, orgId: uuid, name: { type: "string" }, slug: { type: "string" },
    description: { type: ["string", "null"] },
    settings: {
      type: "object", additionalProperties: false, required: ["defaultEnvironments"],
      properties: { defaultEnvironments: { type: "array", items: { type: "string" } } },
    },
    tagIds: { type: "array", items: uuid }, archivedAt: nullableDateTime,
    deletedAt: nullableDateTime, purgeAfter: nullableDateTime,
  },
} as const;
const environmentSchema = {
  type: "object", additionalProperties: false,
  required: ["id", "orgId", "projectId", "name", "slug", "displayOrder", "protected", "deletedAt", "purgeAfter"],
  properties: {
    id: uuid, orgId: uuid, projectId: uuid, name: { type: "string" }, slug: { type: "string" },
    displayOrder: { type: "integer" }, protected: { type: "boolean" },
    deletedAt: nullableDateTime, purgeAfter: nullableDateTime,
  },
} as const;
const secretMetadataProperties = {
  id: uuid, orgId: uuid, projectId: uuid, environmentId: uuid, key: { type: "string" },
  notes: { type: ["string", "null"] }, currentVersion: { type: "integer", minimum: 1 },
  createdAt: dateTime, updatedAt: dateTime,
} as const;
const secretMetadataSchema = {
  type: "object", additionalProperties: false,
  required: Object.keys(secretMetadataProperties), properties: secretMetadataProperties,
} as const;
const secretValueSchema = {
  type: "object", additionalProperties: false,
  required: [...Object.keys(secretMetadataProperties), "value"],
  properties: { ...secretMetadataProperties, value: { type: "string" } },
} as const;
const versionSchema = {
  type: "object", additionalProperties: false,
  required: ["version", "authorUserId", "changeNote", "encryptionKeyVersion", "createdAt", "current"],
  properties: {
    version: { type: "integer", minimum: 1 }, authorUserId: { anyOf: [uuid, { type: "null" }] },
    changeNote: { type: ["string", "null"] }, encryptionKeyVersion: { type: "integer", minimum: 1 },
    createdAt: dateTime, current: { type: "boolean" },
  },
} as const;
const tagSchema = {
  type: "object", additionalProperties: false,
  required: ["id", "name", "color", "createdAt", "updatedAt"],
  properties: { id: uuid, name: { type: "string" }, color: { type: "string" }, createdAt: dateTime, updatedAt: dateTime },
} as const;
const stringMapSchema = { type: "object", additionalProperties: { type: "string" } } as const;

function responseEnvelope(data: unknown, paged = false): Record<string, unknown> {
  return {
    type: "object", additionalProperties: false, required: ["data"],
    properties: {
      data,
      meta: paged
        ? {
            type: "object", additionalProperties: false, required: ["limit", "offset", "total"],
            properties: { limit: { type: "integer" }, offset: { type: "integer" }, total: { type: "integer" } },
          }
        : { type: "object", additionalProperties: true },
    },
  };
}

function apiResponses(data: unknown, paged = false): Record<string, unknown> {
  return { "2xx": responseEnvelope(data, paged), "4xx": errorResponse, "5xx": errorResponse };
}

function listSchema(item: unknown): Record<string, unknown> {
  return { type: "array", items: item };
}

export async function buildApi(dependencies: ApiDependencies): Promise<FastifyInstance> {
  const app = Fastify({ logger: false, ajv: { customOptions: { coerceTypes: true } } });
  await app.register(swagger, {
    openapi: {
      openapi: "3.1.0",
      info: {
        title: "Himitsu API",
        description: "Versioned API for tenant-scoped projects, environments, secrets, versions, and tags.",
        version: "1.0.0",
      },
      tags: [
        { name: "projects" },
        { name: "environments" },
        { name: "secrets" },
        { name: "versions" },
        { name: "tags" },
      ],
    },
  });

  app.setErrorHandler((error, request, reply) => {
    const mapped = mapError(error);
    void reply.status(mapped.statusCode).send({
      error: {
        code: mapped.code,
        message: mapped.message,
        requestId: request.id,
        ...(mapped.details === undefined ? {} : { details: mapped.details }),
      },
    });
  });

  const withTenant = async <T>(
    request: FastifyRequest,
    work: (transaction: TenantTransaction, context: ApiRequestContext) => Promise<T>,
  ): Promise<T> => {
    const context = await dependencies.resolveRequestContext(request);
    if (!context.orgId || !context.userId) {
      throw new ApiError(401, "UNAUTHENTICATED", "An authenticated organization context is required");
    }
    return dependencies.database.withOrg(context.orgId, context.userId, (transaction) =>
      work(transaction, context),
    );
  };

  app.get("/api/v1/openapi.json", {
    schema: {
      operationId: "getOpenApi",
      tags: ["projects"],
      response: { 200: { type: "object", additionalProperties: true } },
    },
  }, async () => app.swagger());

  app.get("/api/v1/projects", {
    schema: { operationId: "listProjects", tags: ["projects"], querystring: pageQuery, response: apiResponses(listSchema(projectSchema), true) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const all = await dependencies.projects.list(transaction, context.userId);
    return paginated(all, request.query as PageQuery);
  }));

  app.post("/api/v1/projects", {
    schema: {
      operationId: "createProject",
      tags: ["projects"],
      body: {
        type: "object", additionalProperties: false, required: ["name", "slug"],
        properties: {
          name: { type: "string", minLength: 1, maxLength: 120 },
          slug: { type: "string", minLength: 1, maxLength: 80 },
          description: { type: ["string", "null"], maxLength: 4000 },
          defaultEnvironments: { type: "array", minItems: 1, maxItems: 20, items: { type: "string" } },
          tagIds: { type: "array", maxItems: 50, items: uuid },
        },
      },
      response: apiResponses(projectSchema),
    },
  }, async (request, reply) => {
    const project = await withTenant(request, (transaction, context) =>
      dependencies.projects.create(
        transaction,
        context.userId,
        request.body as Parameters<ProjectService["create"]>[2],
      ),
    );
    return reply.status(201).send({ data: project });
  });

  app.get("/api/v1/projects/:projectId", {
    schema: { operationId: "getProject", tags: ["projects"], params: idParams({ projectId: uuid }), response: apiResponses(projectSchema) },
  }, async (request) => withTenant(request, async (transaction, context) => ({
    data: await dependencies.projects.getById(transaction, context.userId, params(request).projectId ?? ""),
  })));

  app.patch("/api/v1/projects/:projectId", {
    schema: {
      operationId: "updateProject", tags: ["projects"], params: idParams({ projectId: uuid }),
      body: {
        type: "object", additionalProperties: false, minProperties: 1,
        properties: {
          name: { type: "string", minLength: 1, maxLength: 120 },
          slug: { type: "string", minLength: 1, maxLength: 80 },
          description: { type: ["string", "null"], maxLength: 4000 },
          defaultEnvironments: { type: "array", minItems: 1, maxItems: 20, items: { type: "string" } },
          tagIds: { type: "array", maxItems: 50, items: uuid },
        },
      }, response: apiResponses(projectSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => ({
    data: await dependencies.projects.update(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      request.body as Parameters<ProjectService["update"]>[3],
    ),
  })));

  app.delete("/api/v1/projects/:projectId", {
    schema: { operationId: "deleteProject", tags: ["projects"], params: idParams({ projectId: uuid }), response: apiResponses(projectSchema) },
  }, async (request) => withTenant(request, async (transaction, context) => ({
    data: await dependencies.projects.delete(transaction, context.userId, params(request).projectId ?? ""),
  })));

  registerEnvironmentRoutes(app, dependencies, withTenant);
  registerSecretRoutes(app, dependencies, withTenant);
  registerTagRoutes(app, withTenant);

  await app.ready();
  return app;
}

type WithTenant = <T>(
  request: FastifyRequest,
  work: (transaction: TenantTransaction, context: ApiRequestContext) => Promise<T>,
) => Promise<T>;

function registerEnvironmentRoutes(
  app: FastifyInstance,
  dependencies: ApiDependencies,
  withTenant: WithTenant,
): void {
  const projectEnvironmentParams = idParams({ projectId: uuid, environmentId: uuid });
  app.get("/api/v1/projects/:projectId/environments", {
    schema: { operationId: "listEnvironments", tags: ["environments"], params: idParams({ projectId: uuid }), querystring: pageQuery, response: apiResponses(listSchema(environmentSchema), true) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const all = await dependencies.environments.list(transaction, context.userId, params(request).projectId ?? "");
    return paginated(all, request.query as PageQuery);
  }));
  app.post("/api/v1/projects/:projectId/environments", {
    schema: {
      operationId: "createEnvironment", tags: ["environments"], params: idParams({ projectId: uuid }),
      body: {
        type: "object", additionalProperties: false, required: ["name", "slug"],
        properties: { name: { type: "string", minLength: 1, maxLength: 80 }, slug: { type: "string", minLength: 1, maxLength: 80 }, protected: { type: "boolean" } },
      }, response: apiResponses(environmentSchema),
    },
  }, async (request, reply) => {
    const environment = await withTenant(request, (transaction, context) => dependencies.environments.create(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      request.body as Parameters<EnvironmentService["create"]>[3],
    ));
    return reply.status(201).send({ data: environment });
  });
  app.post("/api/v1/projects/:projectId/environments/reorder", {
    schema: {
      operationId: "reorderEnvironments", tags: ["environments"], params: idParams({ projectId: uuid }),
      body: { type: "object", additionalProperties: false, required: ["environmentIds"], properties: { environmentIds: { type: "array", minItems: 1, maxItems: 50, items: uuid } } },
      response: apiResponses(listSchema(environmentSchema)),
    },
  }, async (request) => withTenant(request, async (transaction, context) => ({ data: await dependencies.environments.reorder(
    transaction,
    context.userId,
    params(request).projectId ?? "",
    (request.body as { environmentIds: string[] }).environmentIds,
  ) })));
  app.get("/api/v1/projects/:projectId/environments/:environmentId", {
    schema: { operationId: "getEnvironment", tags: ["environments"], params: projectEnvironmentParams, response: apiResponses(environmentSchema) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const environment = await dependencies.environments.get(transaction, context.userId, params(request).environmentId ?? "");
    if (environment.projectId !== params(request).projectId) throw new EnvironmentError("NOT_FOUND", "Environment not found");
    return { data: environment };
  }));
  app.patch("/api/v1/projects/:projectId/environments/:environmentId", {
    schema: {
      operationId: "updateEnvironment", tags: ["environments"], params: projectEnvironmentParams,
      body: { type: "object", additionalProperties: false, minProperties: 1, properties: { name: { type: "string", minLength: 1, maxLength: 80 }, slug: { type: "string", minLength: 1, maxLength: 80 }, protected: { type: "boolean" } } },
      response: apiResponses(environmentSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const existing = await dependencies.environments.get(transaction, context.userId, params(request).environmentId ?? "");
    if (existing.projectId !== params(request).projectId) throw new EnvironmentError("NOT_FOUND", "Environment not found");
    return { data: await dependencies.environments.update(
      transaction,
      context.userId,
      existing.id,
      request.body as Parameters<EnvironmentService["update"]>[3],
    ) };
  }));
  app.delete("/api/v1/projects/:projectId/environments/:environmentId", {
    schema: {
      operationId: "deleteEnvironment", tags: ["environments"], params: projectEnvironmentParams,
      querystring: { type: "object", additionalProperties: false, properties: { confirmSecrets: { type: "boolean", default: false } } },
      response: apiResponses(environmentSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const existing = await dependencies.environments.get(transaction, context.userId, params(request).environmentId ?? "");
    if (existing.projectId !== params(request).projectId) throw new EnvironmentError("NOT_FOUND", "Environment not found");
    return { data: await dependencies.environments.delete(
      transaction,
      context.userId,
      existing.id,
      { confirmSecrets: (request.query as { confirmSecrets?: boolean }).confirmSecrets ?? false },
    ) };
  }));
}

function registerSecretRoutes(
  app: FastifyInstance,
  dependencies: ApiDependencies,
  withTenant: WithTenant,
): void {
  const scopeParams = idParams({ projectId: uuid, environmentId: uuid });
  const secretParams = idParams({ secretId: uuid });
  const setSecretBody = {
    type: "object", additionalProperties: false, required: ["key", "value"],
    properties: {
      key: { type: "string", minLength: 1, maxLength: 255 },
      value: { type: "string" }, notes: { type: ["string", "null"], maxLength: 4000 },
      changeNote: { type: ["string", "null"], maxLength: 1000 }, allowNonConformingKey: { type: "boolean" },
    },
  } as const;
  app.get("/api/v1/projects/:projectId/environments/:environmentId/secrets", {
    schema: { operationId: "listSecrets", tags: ["secrets"], params: scopeParams, querystring: pageQuery, response: apiResponses(listSchema(secretMetadataSchema), true) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const all = await dependencies.secrets.list(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      params(request).environmentId ?? "",
    );
    return paginated(all, request.query as PageQuery);
  }));
  app.post("/api/v1/projects/:projectId/environments/:environmentId/secrets", {
    schema: { operationId: "createSecret", tags: ["secrets"], params: scopeParams, body: setSecretBody, response: apiResponses(secretMetadataSchema) },
  }, async (request, reply) => {
    const secret = await withTenant(request, (transaction, context) => dependencies.secrets.create(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      params(request).environmentId ?? "",
      request.body as Parameters<SecretService["create"]>[4],
    ));
    return reply.status(201).send({ data: secret });
  });
  app.post("/api/v1/projects/:projectId/environments/:environmentId/secrets/bulk", {
    schema: {
      operationId: "bulkSetSecrets", tags: ["secrets"], params: scopeParams,
      body: { type: "object", additionalProperties: false, required: ["secrets"], properties: { secrets: { type: "array", minItems: 1, maxItems: 100, items: setSecretBody } } },
      response: apiResponses(listSchema(secretMetadataSchema)),
    },
  }, async (request) => withTenant(request, async (transaction, context) => ({ data: await dependencies.secrets.bulkSet(
    transaction,
    context.userId,
    params(request).projectId ?? "",
    params(request).environmentId ?? "",
    (request.body as { secrets: Parameters<SecretService["bulkSet"]>[4] }).secrets,
  ) })));
  app.post("/api/v1/projects/:projectId/environments/:environmentId/secrets/bulk-get", {
    schema: {
      operationId: "bulkGetSecrets", tags: ["secrets"], params: scopeParams,
      body: { type: "object", additionalProperties: false, properties: { keys: { type: "array", minItems: 1, maxItems: 100, uniqueItems: true, items: { type: "string" } } } },
      response: apiResponses(stringMapSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const projectId = params(request).projectId ?? "";
    const environmentId = params(request).environmentId ?? "";
    const metadata = await dependencies.secrets.list(transaction, context.userId, projectId, environmentId);
    const requested = (request.body as { keys?: string[] }).keys;
    const selected = requested === undefined
      ? metadata
      : metadata.filter(({ key }) => requested.includes(key));
    const values = await Promise.all(selected.map(({ id }) => dependencies.secrets.get(transaction, context.userId, id)));
    return { data: Object.fromEntries(values.map(({ key, value }) => [key, value])), meta: { count: values.length } };
  }));
  app.get("/api/v1/secrets/:secretId", {
    schema: { operationId: "getSecret", tags: ["secrets"], params: secretParams, response: apiResponses(secretValueSchema) },
  }, async (request) => withTenant(request, async (transaction, context) => ({ data: await dependencies.secrets.get(
    transaction,
    context.userId,
    params(request).secretId ?? "",
  ) })));
  app.patch("/api/v1/secrets/:secretId", {
    schema: {
      operationId: "updateSecret", tags: ["secrets"], params: secretParams,
      body: { type: "object", additionalProperties: false, required: ["value"], properties: { value: { type: "string" }, notes: { type: ["string", "null"], maxLength: 4000 }, changeNote: { type: ["string", "null"], maxLength: 1000 } } },
      response: apiResponses(secretMetadataSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => ({ data: await dependencies.secrets.update(
    transaction,
    context.userId,
    params(request).secretId ?? "",
    request.body as Parameters<SecretService["update"]>[3],
  ) })));
  app.delete("/api/v1/secrets/:secretId", {
    schema: { operationId: "deleteSecret", tags: ["secrets"], params: secretParams, response: apiResponses(secretMetadataSchema) },
  }, async (request) => withTenant(request, async (transaction, context) => ({ data: await dependencies.secrets.delete(
    transaction,
    context.userId,
    params(request).secretId ?? "",
  ) })));
  app.get("/api/v1/secrets/:secretId/versions", {
    schema: { operationId: "listSecretVersions", tags: ["versions"], params: secretParams, querystring: pageQuery, response: apiResponses(listSchema(versionSchema), true) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const all = await dependencies.secrets.listVersions(transaction, context.userId, params(request).secretId ?? "");
    return paginated(all, request.query as PageQuery);
  }));
}

function registerTagRoutes(app: FastifyInstance, withTenant: WithTenant): void {
  const resolver = new AuthorizationContextResolver();
  app.get("/api/v1/tags", {
    schema: { operationId: "listTags", tags: ["tags"], querystring: pageQuery, response: apiResponses(listSchema(tagSchema), true) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    requirePermission(await resolver.resolve(transaction, context.userId), "org.settings.read");
    const { limit, offset } = pagination(request.query as PageQuery);
    const [rows, count] = await Promise.all([
      transaction.query<TagRow>("SELECT id, name, color, created_at, updated_at FROM tags ORDER BY lower(name), id LIMIT $1 OFFSET $2", [limit, offset]),
      transaction.query<{ count: string }>("SELECT count(*)::text AS count FROM tags"),
    ]);
    return { data: rows.rows.map(tagFromRow), meta: { limit, offset, total: Number(count.rows[0]?.count ?? 0) } };
  }));
  app.post("/api/v1/tags", {
    schema: {
      operationId: "createTag", tags: ["tags"],
      body: { type: "object", additionalProperties: false, required: ["name", "color"], properties: { name: { type: "string", minLength: 1, maxLength: 80 }, color: { type: "string", pattern: "^#[0-9A-Fa-f]{6}$" } } },
      response: apiResponses(tagSchema),
    },
  }, async (request, reply) => {
    const tag = await withTenant(request, async (transaction, context) => {
      requirePermission(await resolver.resolve(transaction, context.userId), "org.settings.update");
      const input = request.body as { name: string; color: string };
      const inserted = await transaction.query<TagRow>(
        `INSERT INTO tags (org_id, name, color) VALUES ($1, $2, $3)
         RETURNING id, name, color, created_at, updated_at`,
        [transaction.orgId, tagName(input.name), input.color.toUpperCase()],
      );
      const row = inserted.rows[0];
      if (row === undefined) throw new Error("Tag insertion returned no row");
      return tagFromRow(row);
    });
    return reply.status(201).send({ data: tag });
  });
  app.patch("/api/v1/tags/:tagId", {
    schema: {
      operationId: "updateTag", tags: ["tags"], params: idParams({ tagId: uuid }),
      body: { type: "object", additionalProperties: false, minProperties: 1, properties: { name: { type: "string", minLength: 1, maxLength: 80 }, color: { type: "string", pattern: "^#[0-9A-Fa-f]{6}$" } } },
      response: apiResponses(tagSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    requirePermission(await resolver.resolve(transaction, context.userId), "org.settings.update");
    const input = request.body as { name?: string; color?: string };
    const updated = await transaction.query<TagRow>(
      `UPDATE tags SET name = COALESCE($1, name), color = COALESCE($2, color), updated_at = now()
       WHERE id = $3 RETURNING id, name, color, created_at, updated_at`,
      [input.name === undefined ? null : tagName(input.name), input.color?.toUpperCase() ?? null, params(request).tagId],
    );
    const row = updated.rows[0];
    if (row === undefined) throw new ApiError(404, "NOT_FOUND", "Tag not found");
    return { data: tagFromRow(row) };
  }));
  app.delete("/api/v1/tags/:tagId", {
    schema: { operationId: "deleteTag", tags: ["tags"], params: idParams({ tagId: uuid }), response: apiResponses(tagSchema) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    requirePermission(await resolver.resolve(transaction, context.userId), "org.settings.update");
    const deleted = await transaction.query<TagRow>(
      "DELETE FROM tags WHERE id = $1 RETURNING id, name, color, created_at, updated_at",
      [params(request).tagId],
    );
    const row = deleted.rows[0];
    if (row === undefined) throw new ApiError(404, "NOT_FOUND", "Tag not found");
    return { data: tagFromRow(row) };
  }));
}

function params(request: FastifyRequest): IdParams {
  return request.params as IdParams;
}

function pagination(query: PageQuery): { limit: number; offset: number } {
  return { limit: query.limit ?? 50, offset: query.offset ?? 0 };
}

function paginated<T>(all: readonly T[], query: PageQuery): { data: readonly T[]; meta: Record<string, number> } {
  const { limit, offset } = pagination(query);
  return { data: all.slice(offset, offset + limit), meta: { limit, offset, total: all.length } };
}

function tagFromRow(row: TagRow): Record<string, unknown> {
  return { id: row.id, name: row.name, color: row.color, createdAt: row.created_at, updatedAt: row.updated_at };
}

function tagName(name: string): string {
  const normalized = name.trim();
  if (normalized.length < 1 || normalized.length > 80) {
    throw new ApiError(400, "INVALID_INPUT", "Tag name must be between 1 and 80 characters");
  }
  return normalized;
}

function mapError(error: unknown): ApiError {
  if (!(error instanceof Error)) return new ApiError(500, "INTERNAL_ERROR", "An unexpected error occurred");
  if (error instanceof ApiError) return error;
  const validation = (error as Error & { validation?: unknown }).validation;
  if (validation !== undefined) {
    return new ApiError(400, "INVALID_REQUEST", "Request validation failed", { validation });
  }
  if (error instanceof AuthorizationError) return new ApiError(403, "FORBIDDEN", "Permission denied");
  if (error instanceof ProjectError || error instanceof EnvironmentError || error instanceof SecretError) {
    if (error.code === "NOT_FOUND") return new ApiError(404, "NOT_FOUND", error.message);
    if (error.code.endsWith("EXISTS")) return new ApiError(409, error.code, error.message);
    return new ApiError(400, error.code, error.message);
  }
  if (error instanceof TenancyError) {
    if (error.code === "MEMBERSHIP_REQUIRED") return new ApiError(403, "FORBIDDEN", "Active organization membership is required");
    return new ApiError(400, error.code, error.message);
  }
  if ((error as { code?: string }).code === "23505") return new ApiError(409, "CONFLICT", "Resource already exists");
  return new ApiError(500, "INTERNAL_ERROR", "An unexpected error occurred");
}
