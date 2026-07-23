import swagger from "@fastify/swagger";
import { ApiKeyError, type ApiKeyPrincipal, type ApiKeyService } from "@himitsu/api-keys";
import { AuditError, type AuditEventFilters, type TransactionalAuditLog } from "@himitsu/audit";
import { AuthError, sessionCookie, type AuthService } from "@himitsu/auth";
import {
  AuthorizationContextResolver,
  AuthorizationError,
  requirePermission,
  type Permission,
} from "@himitsu/authz";
import { ConsistencyError, type ConsistencyService } from "@himitsu/consistency";
import { EnvironmentError, type EnvironmentService } from "@himitsu/environments";
import {
  buildDotenvPreview,
  buildJsonImportPreview,
  parseDotenv,
  parseJsonSecrets,
} from "@himitsu/imports";
import { ProjectError, type ProjectService } from "@himitsu/projects";
import { SecretError, type SecretService } from "@himitsu/secrets";
import { TenancyError, type TenantDatabase, type TenantTransaction } from "@himitsu/tenancy";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";

export type ApiActor =
  | { readonly type: "user"; readonly userId: string; readonly sessionId: string }
  | { readonly type: "api_key"; readonly apiKeyId: string; readonly prefix: string };

export interface ApiRequestContext {
  readonly orgId: string;
  readonly userId: string;
  readonly actor: ApiActor;
  readonly apiKey: ApiKeyPrincipal | null;
}

export interface ApiRateLimitOptions {
  readonly windowMs?: number;
  readonly perIp?: number;
  readonly perApiKey?: number;
  readonly now?: () => number;
}

export interface ApiDependencies {
  readonly database: TenantDatabase;
  readonly auth: AuthService;
  readonly apiKeys: ApiKeyService;
  readonly audit: TransactionalAuditLog;
  readonly projects: ProjectService;
  readonly environments: EnvironmentService;
  readonly secrets: SecretService;
  readonly consistency: ConsistencyService;
  readonly rateLimits?: ApiRateLimitOptions;
  readonly readiness?: () => Promise<void>;
  readonly logger?: boolean;
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
  apiKeyId?: string;
  projectId?: string;
  environmentId?: string;
  secretId?: string;
  tagId?: string;
}

interface PageQuery {
  limit?: number;
  offset?: number;
  search?: string;
  tagId?: string;
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
const searchablePageQuery = {
  type: "object",
  additionalProperties: false,
  properties: {
    ...pageQuery.properties,
    search: { type: "string", maxLength: 200 },
    tagId: uuid,
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
  required: ["id", "orgId", "name", "slug", "description", "settings", "tagIds", "tags", "archivedAt", "deletedAt", "purgeAfter"],
  properties: {
    id: uuid, orgId: uuid, name: { type: "string" }, slug: { type: "string" },
    description: { type: ["string", "null"] },
    settings: {
      type: "object", additionalProperties: false, required: ["defaultEnvironments"],
      properties: { defaultEnvironments: { type: "array", items: { type: "string" } } },
    },
    tagIds: { type: "array", items: uuid }, archivedAt: nullableDateTime,
    tags: { type: "array", items: { type: "object", additionalProperties: false, required: ["id", "name", "color"], properties: { id: uuid, name: { type: "string" }, color: { type: "string" } } } },
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
  tagIds: { type: "array", items: uuid },
  tags: { type: "array", items: { type: "object", additionalProperties: false, required: ["id", "name", "color"], properties: { id: uuid, name: { type: "string" }, color: { type: "string" } } } },
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
const versionComparisonSchema = {
  type: "object", additionalProperties: false,
  required: ["fromVersion", "toVersion", "changed", "masked"],
  properties: {
    fromVersion: { type: "integer", minimum: 1 },
    toVersion: { type: "integer", minimum: 1 },
    changed: { type: "boolean" },
    masked: { type: "boolean" },
    fromValue: { type: "string" },
    toValue: { type: "string" },
  },
} as const;
const dotenvIssueSchema = {
  type: "object",
  additionalProperties: false,
  required: ["line", "code", "message"],
  properties: {
    line: { type: "integer", minimum: 1 },
    code: { type: "string" },
    message: { type: "string" },
    key: { type: "string" },
  },
} as const;
const dotenvPreviewSchema = {
  type: "object",
  additionalProperties: false,
  required: ["entries", "conflicts", "summary"],
  properties: {
    entries: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["key", "line", "operation"],
        properties: {
          key: { type: "string" },
          line: { type: "integer" },
          operation: { type: "string", enum: ["add", "update"] },
        },
      },
    },
    conflicts: { type: "array", items: dotenvIssueSchema },
    summary: {
      type: "object",
      additionalProperties: false,
      required: ["adds", "updates", "conflicts"],
      properties: {
        adds: { type: "integer" },
        updates: { type: "integer" },
        conflicts: { type: "integer" },
      },
    },
  },
} as const;
const importResultSchema = {
  type: "object",
  additionalProperties: false,
  required: ["secrets", "summary"],
  properties: {
    secrets: { type: "array", items: secretMetadataSchema },
    summary: {
      type: "object",
      additionalProperties: false,
      required: ["requested", "created", "updated", "skipped"],
      properties: {
        requested: { type: "integer" },
        created: { type: "integer" },
        updated: { type: "integer" },
        skipped: { type: "integer" },
      },
    },
  },
} as const;
const promotionPreviewSchema = {
  type: "object",
  additionalProperties: false,
  required: ["sourceEnvironmentId", "targetEnvironmentId", "items", "summary"],
  properties: {
    sourceEnvironmentId: uuid,
    targetEnvironmentId: uuid,
    items: {
      type: "array",
      items: {
        type: "object", additionalProperties: false,
        required: ["key", "action", "changed", "sourceVersion", "targetVersion"],
        properties: {
          key: { type: "string" }, action: { type: "string", enum: ["create", "overwrite"] },
          changed: { type: "boolean" },
          sourceVersion: { type: "integer", minimum: 1 }, targetVersion: { type: ["integer", "null"], minimum: 1 },
        },
      },
    },
    summary: {
      type: "object", additionalProperties: false,
      required: ["selected", "created", "overwritten"],
      properties: { selected: { type: "integer" }, created: { type: "integer" }, overwritten: { type: "integer" } },
    },
  },
} as const;
const promotionResultSchema = {
  ...promotionPreviewSchema,
  required: [...promotionPreviewSchema.required, "secrets"],
  properties: { ...promotionPreviewSchema.properties, secrets: { type: "array", items: secretMetadataSchema } },
} as const;
const jsonIssueSchema = {
  type: "object",
  additionalProperties: false,
  required: ["path", "code", "message"],
  properties: { path: { type: "string" }, code: { type: "string" }, message: { type: "string" } },
} as const;
const jsonImportPreviewSchema = {
  type: "object",
  additionalProperties: false,
  required: ["entries", "conflicts", "summary"],
  properties: {
    entries: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["key", "path", "operation"],
        properties: { key: { type: "string" }, path: { type: "string" }, operation: { type: "string", enum: ["add", "update"] } },
      },
    },
    conflicts: { type: "array", items: jsonIssueSchema },
    summary: dotenvPreviewSchema.properties.summary,
  },
} as const;
const tagSchema = {
  type: "object", additionalProperties: false,
  required: ["id", "name", "color", "createdAt", "updatedAt"],
  properties: { id: uuid, name: { type: "string" }, color: { type: "string" }, createdAt: dateTime, updatedAt: dateTime },
} as const;
const nullableUuid = { anyOf: [uuid, { type: "null" }] } as const;
const apiKeySchema = {
  type: "object", additionalProperties: false,
  required: ["id", "orgId", "projectId", "environmentId", "name", "prefix", "access", "createdAt", "expiresAt", "lastUsedAt", "revokedAt"],
  properties: {
    id: uuid, orgId: uuid, projectId: nullableUuid, environmentId: nullableUuid,
    name: { type: "string" }, prefix: { type: "string", pattern: "^himi_[0-9a-f]{16}$" },
    access: { type: "string", enum: ["read_only", "read_write"] }, createdAt: dateTime,
    expiresAt: nullableDateTime, lastUsedAt: nullableDateTime, revokedAt: nullableDateTime,
  },
} as const;
const createdApiKeySchema = {
  type: "object", additionalProperties: false, required: ["apiKey", "token"],
  properties: { apiKey: apiKeySchema, token: { type: "string", pattern: "^himi_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$" } },
} as const;
const stringMapSchema = { type: "object", additionalProperties: { type: "string" } } as const;
const runtimeConfigSchema = {
  type: "object", additionalProperties: false, required: ["configVersion", "secrets"],
  properties: {
    configVersion: { type: "integer", minimum: 0 },
    secrets: stringMapSchema,
  },
} as const;
const secretExportSchema = {
  type: "object", additionalProperties: false,
  required: ["format", "filename", "mimeType", "content", "secretCount", "nested"],
  properties: {
    format: { type: "string", enum: ["dotenv", "json", "shell"] },
    filename: { type: "string" }, mimeType: { type: "string" }, content: { type: "string" },
    secretCount: { type: "integer", minimum: 0 }, nested: { type: "boolean" },
  },
} as const;
const consistencyFindingSchema = {
  type: "object", additionalProperties: false,
  required: ["id", "type", "severity", "key", "keys", "environmentIds", "missingEnvironmentIds", "disposition", "dispositionNote", "dispositionUpdatedAt"],
  properties: {
    id: { type: "string" },
    type: { type: "string", enum: ["missing_key", "empty_value", "placeholder_value", "naming_violation", "case_duplicate"] },
    severity: { type: "string", enum: ["warning", "error"] },
    key: { type: "string" },
    keys: { type: "array", items: { type: "string" } },
    environmentIds: { type: "array", items: uuid },
    missingEnvironmentIds: { type: "array", items: uuid },
    disposition: { type: ["string", "null"], enum: ["acknowledged", "ignored", null] },
    dispositionNote: { type: ["string", "null"] },
    dispositionUpdatedAt: nullableDateTime,
  },
} as const;
const consistencyReportSchema = {
  type: "object", additionalProperties: false,
  required: ["projectId", "sourceFingerprint", "computedAt", "cached", "environments", "matrix", "findings", "counts", "summary"],
  properties: {
    projectId: uuid,
    sourceFingerprint: { type: "string", pattern: "^[0-9a-f]{64}$" },
    computedAt: dateTime,
    cached: { type: "boolean" },
    environments: { type: "array", items: { type: "object", additionalProperties: false, required: ["id", "slug"], properties: { id: uuid, slug: { type: "string" } } } },
    matrix: { type: "array", items: {
      type: "object", additionalProperties: false, required: ["key", "keys", "cells"],
      properties: {
        key: { type: "string" }, keys: { type: "array", items: { type: "string" } },
        cells: { type: "array", items: { type: "object", additionalProperties: false, required: ["environmentId", "state", "secretId"], properties: {
          environmentId: uuid, state: { type: "string", enum: ["present", "missing", "empty"] }, secretId: nullableUuid,
        } } },
      },
    } },
    findings: { type: "array", items: consistencyFindingSchema },
    counts: { type: "object", additionalProperties: false, required: ["error", "warning"], properties: { error: { type: "integer" }, warning: { type: "integer" } } },
    summary: { type: "object", additionalProperties: false, required: ["healthy", "exitCode", "totalFindings", "activeFindings", "errors", "warnings"], properties: {
      healthy: { type: "boolean" }, exitCode: { type: "integer", enum: [0, 1] }, totalFindings: { type: "integer" }, activeFindings: { type: "integer" }, errors: { type: "integer" }, warnings: { type: "integer" },
    } },
  },
} as const;
const auditEventSchema = {
  type: "object", additionalProperties: false,
  required: ["id", "actor", "action", "resource", "projectId", "environmentId", "ip", "userAgent", "metadata", "occurredAt"],
  properties: {
    id: { type: "string", pattern: "^[0-9]+$" },
    actor: { type: "object", additionalProperties: false, required: ["type", "id", "label"], properties: {
      type: { type: "string", enum: ["user", "api_key", "system"] }, id: { type: ["string", "null"] }, label: { type: "string" },
    } },
    action: { type: "string" },
    resource: { type: "object", additionalProperties: false, required: ["type", "id"], properties: { type: { type: "string" }, id: { type: ["string", "null"] } } },
    projectId: nullableUuid, environmentId: nullableUuid, ip: { type: ["string", "null"] }, userAgent: { type: ["string", "null"] },
    metadata: { type: "object", additionalProperties: true }, occurredAt: dateTime,
  },
} as const;
const auditPageSchema = {
  type: "object", additionalProperties: false, required: ["events", "nextCursor"],
  properties: { events: { type: "array", items: auditEventSchema }, nextCursor: { type: ["string", "null"] } },
} as const;
const auditExportSchema = {
  type: "object", additionalProperties: false, required: ["format", "filename", "mimeType", "content", "eventCount", "truncated"],
  properties: {
    format: { type: "string", enum: ["csv", "json"] }, filename: { type: "string" }, mimeType: { type: "string" },
    content: { type: "string" }, eventCount: { type: "integer" }, truncated: { type: "boolean" },
  },
} as const;
const auditFilterProperties = {
  actor: { type: "string", maxLength: 320 }, action: { type: "string", maxLength: 120 },
  projectId: uuid, environmentId: uuid, from: dateTime, to: dateTime,
  resource: { type: "string", maxLength: 200 },
} as const;

export const apiRoutePermissions = Object.freeze({
  listProjects: "project.read",
  createProject: "project.create",
  getProject: "project.read",
  updateProject: "project.update",
  deleteProject: "project.delete",
  getProjectConsistency: "secret.read",
  listAuditEvents: "audit.read",
  exportAuditEvents: "audit.export",
  getAuditSettings: "audit.read",
  updateAuditSettings: "org.settings.update",
  listEnvironments: "environment.read",
  createEnvironment: "environment.create",
  reorderEnvironments: "environment.update",
  getEnvironment: "environment.read",
  updateEnvironment: "environment.update",
  deleteEnvironment: "environment.delete",
  listSecrets: "secret.read",
  createSecret: "secret.write",
  bulkSetSecrets: "secret.write",
  bulkGetSecrets: "secret.read",
  fetchRuntimeSecrets: "secret.read",
  exportSecrets: "secret.read",
  previewSecretPromotion: "secret.write",
  promoteSecrets: "secret.write",
  getSecret: "secret.read",
  updateSecret: "secret.write",
  deleteSecret: "secret.delete",
  listSecretVersions: "secret.read",
  compareSecretVersions: "secret.read",
  rollbackSecretVersion: "secret.write",
  previewDotenvImport: "secret.write",
  commitDotenvImport: "secret.write",
  previewJsonImport: "secret.write",
  commitJsonImport: "secret.write",
  listTags: "org.settings.read",
  createTag: "org.settings.update",
  updateTag: "org.settings.update",
  mergeTag: "org.settings.update",
  deleteTag: "org.settings.update",
  listApiKeys: "api_key.read",
  createApiKey: "api_key.create",
  revokeApiKey: "api_key.revoke",
} satisfies Readonly<Record<string, Permission>>);

export const securityHeaders = Object.freeze({
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), geolocation=(), microphone=()",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
} as const);

export interface RateLimitDecision {
  readonly allowed: boolean;
  readonly limit: number;
  readonly remaining: number;
  readonly resetAfterSeconds: number;
}

interface RateLimitBucket {
  count: number;
  resetAt: number;
}

export class InMemoryRateLimiter {
  readonly #windowMs: number;
  readonly #perIp: number;
  readonly #perApiKey: number;
  readonly #now: () => number;
  readonly #buckets = new Map<string, RateLimitBucket>();
  #operations = 0;

  constructor(options: ApiRateLimitOptions = {}) {
    this.#windowMs = positiveInteger(options.windowMs ?? 60_000, "Rate-limit window");
    this.#perIp = positiveInteger(options.perIp ?? 300, "Per-IP rate limit");
    this.#perApiKey = positiveInteger(options.perApiKey ?? 120, "Per-key rate limit");
    this.#now = options.now ?? Date.now;
  }

  consume(kind: "ip" | "api_key", identity: string): RateLimitDecision {
    const now = this.#now();
    const limit = kind === "ip" ? this.#perIp : this.#perApiKey;
    const bucketKey = `${kind}:${identity}`;
    const current = this.#buckets.get(bucketKey);
    const bucket = current === undefined || current.resetAt <= now
      ? { count: 0, resetAt: now + this.#windowMs }
      : current;
    bucket.count += 1;
    this.#buckets.set(bucketKey, bucket);
    this.#operations += 1;
    if (this.#operations % 1000 === 0) {
      for (const [key, candidate] of this.#buckets) {
        if (candidate.resetAt <= now) this.#buckets.delete(key);
      }
    }
    return {
      allowed: bucket.count <= limit,
      limit,
      remaining: Math.max(0, limit - bucket.count),
      resetAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)),
    };
  }
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function applyRateLimitHeaders(reply: FastifyReply, decision: RateLimitDecision): void {
  void reply.header("RateLimit-Limit", decision.limit.toString());
  void reply.header("RateLimit-Remaining", decision.remaining.toString());
  void reply.header("RateLimit-Reset", decision.resetAfterSeconds.toString());
  void reply.header("RateLimit-Policy", `${decision.limit};w=${decision.resetAfterSeconds}`);
  if (!decision.allowed) {
    void reply.header("Retry-After", decision.resetAfterSeconds.toString());
    throw new ApiError(429, "RATE_LIMITED", "Too many requests");
  }
}

function cookieValue(header: string | undefined, name: string): string | null {
  if (header === undefined) return null;
  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0 || pair.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(pair.slice(separator + 1).trim());
    } catch {
      throw new ApiError(401, "UNAUTHENTICATED", "Session cookie is invalid");
    }
  }
  return null;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function clientDetails(request: FastifyRequest): { ip: string; userAgent?: string } {
  const userAgent = headerValue(request.headers["user-agent"]);
  return { ip: request.ip, ...(userAgent === undefined ? {} : { userAgent }) };
}

function isUnsafeMethod(method: string): boolean {
  return !(["GET", "HEAD", "OPTIONS"] as const).includes(method as "GET" | "HEAD" | "OPTIONS");
}

async function authenticateRequest(
  dependencies: ApiDependencies,
  request: FastifyRequest,
): Promise<ApiRequestContext> {
  const authorization = headerValue(request.headers.authorization);
  const sessionToken = cookieValue(request.headers.cookie, sessionCookie.name);
  if (authorization !== undefined && sessionToken !== null) {
    throw new ApiError(401, "UNAUTHENTICATED", "Use either a session or bearer credential, not both");
  }
  if (authorization !== undefined) {
    const bearer = /^Bearer ([^\s]+)$/i.exec(authorization)?.[1];
    if (bearer === undefined) throw new ApiError(401, "UNAUTHENTICATED", "Bearer API token is required");
    const principal = await dependencies.apiKeys.authenticate(bearer, clientDetails(request));
    return {
      orgId: principal.orgId,
      userId: principal.userId,
      actor: { type: "api_key", apiKeyId: principal.apiKeyId, prefix: principal.prefix },
      apiKey: principal,
    };
  }
  if (sessionToken === null) throw new ApiError(401, "UNAUTHENTICATED", "Authentication is required");
  try {
    const session = await dependencies.auth.authenticate(sessionToken);
    if (session.activeOrgId === null) {
      throw new AuthError("INVALID_SESSION", "Select an active organization");
    }
    if (isUnsafeMethod(request.method)) {
      const csrf = headerValue(request.headers["x-csrf-token"]);
      if (csrf === undefined) throw new AuthError("INVALID_CSRF", "CSRF token is required");
      dependencies.auth.verifyCsrf(session, csrf);
    }
    return {
      orgId: session.activeOrgId,
      userId: session.userId,
      actor: { type: "user", userId: session.userId, sessionId: session.sessionId },
      apiKey: null,
    };
  } catch (error) {
    if (error instanceof AuthError) {
      const failed = await dependencies.auth.failedSessionContext(sessionToken);
      if (failed !== null) {
        try {
          await dependencies.database.withOrg(failed.activeOrgId, failed.userId, (transaction) =>
            dependencies.audit.recordInTransaction(transaction, {
              orgId: failed.activeOrgId,
              actor: { type: "user", id: failed.userId },
              action: "auth.login_failed",
              resource: { type: "session", id: failed.sessionId },
              ...clientDetails(request),
              details: { method: "session", reason: error.code },
            }));
        } catch {
          // A removed membership cannot write a tenant audit row; authentication still fails closed.
        }
      }
    }
    throw error;
  }
}

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
  const app = Fastify({ logger: dependencies.logger ?? false, ajv: { customOptions: { coerceTypes: true } } });
  const contexts = new WeakMap<FastifyRequest, ApiRequestContext>();
  const rateLimiter = new InMemoryRateLimiter(dependencies.rateLimits);
  const routeAuthorization = new AuthorizationContextResolver();
  const startedAt = Date.now();
  let requestCount = 0;
  let errorCount = 0;
  await app.register(swagger, {
    openapi: {
      openapi: "3.1.0",
      info: {
        title: "Himitsu API",
        description: "Versioned API for tenant-scoped projects, environments, secrets, versions, and tags.",
        version: "1.0.0",
      },
      tags: [
        { name: "auth" },
        { name: "projects" },
        { name: "environments" },
        { name: "secrets" },
        { name: "versions" },
        { name: "imports" },
        { name: "consistency" },
        { name: "audit" },
        { name: "tags" },
        { name: "api-keys" },
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

  app.addHook("onSend", async (_request, reply, payload) => {
    for (const [name, value] of Object.entries(securityHeaders)) void reply.header(name, value);
    return payload;
  });

  app.addHook("onResponse", async (_request, reply) => {
    requestCount += 1;
    if (reply.statusCode >= 500) errorCount += 1;
  });

  app.addHook("onRequest", async (request, reply) => {
    if (["/api/v1/openapi.json", "/health/live", "/health/ready", "/metrics"].includes(routePath(request))) return;
    applyRateLimitHeaders(reply, rateLimiter.consume("ip", request.ip));
    if (routePath(request) === "/api/v1/cli/login") return;
    const context = await authenticateRequest(dependencies, request);
    if (context.apiKey !== null) {
      applyRateLimitHeaders(reply, rateLimiter.consume("api_key", context.apiKey.apiKeyId));
    }
    contexts.set(request, context);
  });

  app.get("/health/live", async () => ({ status: "ok" }));

  app.get("/health/ready", async (_request, reply) => {
    try {
      await dependencies.readiness?.();
      return { status: "ready" };
    } catch {
      return reply.status(503).send({ status: "not_ready" });
    }
  });

  app.get("/metrics", async (_request, reply) => {
    void reply.type("text/plain; version=0.0.4; charset=utf-8");
    const uptime = Math.max(0, (Date.now() - startedAt) / 1000);
    return [
      "# HELP himitsu_http_requests_total Total HTTP responses served.",
      "# TYPE himitsu_http_requests_total counter",
      `himitsu_http_requests_total ${requestCount}`,
      "# HELP himitsu_http_errors_total Total HTTP responses with a 5xx status.",
      "# TYPE himitsu_http_errors_total counter",
      `himitsu_http_errors_total ${errorCount}`,
      "# HELP himitsu_process_uptime_seconds Process uptime in seconds.",
      "# TYPE himitsu_process_uptime_seconds gauge",
      `himitsu_process_uptime_seconds ${uptime.toFixed(3)}`,
      "",
    ].join("\n");
  });

  const withTenant = async <T>(
    request: FastifyRequest,
    work: (transaction: TenantTransaction, context: ApiRequestContext) => Promise<T>,
  ): Promise<T> => {
    const context = contexts.get(request);
    if (context === undefined) throw new ApiError(401, "UNAUTHENTICATED", "Authentication is required");
    return dependencies.database.withOrg(context.orgId, context.userId, async (transaction) => {
      await enforceApiKeyScope(request, transaction, context);
      await enforceRoutePermission(request, transaction, context, routeAuthorization);
      return work(transaction, context);
    });
  };

  app.get("/api/v1/openapi.json", {
    schema: {
      operationId: "getOpenApi",
      tags: ["projects"],
      response: { 200: { type: "object", additionalProperties: true } },
    },
  }, async () => app.swagger());

  app.post("/api/v1/cli/login", {
    schema: {
      tags: ["auth"],
      body: { type: "object", additionalProperties: false, required: ["email", "password"], properties: {
        email: { type: "string", format: "email", maxLength: 320 }, password: { type: "string", minLength: 1, maxLength: 1024 }, orgId: uuid,
      } },
      response: apiResponses({
        type: "object", additionalProperties: false,
        required: ["sessionToken", "csrfToken", "expiresAt", "user", "organizations", "activeOrgId"],
        properties: {
          sessionToken: { type: "string" }, csrfToken: { type: "string" }, expiresAt: dateTime,
          user: { type: "object", additionalProperties: false, required: ["id", "email"], properties: { id: uuid, email: { type: "string" } } },
          organizations: { type: "array", items: { type: "object", additionalProperties: false, required: ["id", "name", "slug", "role", "active"], properties: {
            id: uuid, name: { type: "string" }, slug: { type: "string" }, role: { type: "string", enum: ["owner", "admin", "member", "read_only"] }, active: { type: "boolean" },
          } } },
          activeOrgId: nullableUuid,
        },
      }),
    },
  }, async (request) => {
    const input = request.body as { email: string; password: string; orgId?: string };
    const credentials = await dependencies.auth.login(input.email, input.password, clientDetails(request));
    const session = await dependencies.auth.authenticate(credentials.sessionToken);
    const organizations = await dependencies.database.listOrganizationOptions(credentials.user.id, null);
    const selectedOrgId = input.orgId ?? (organizations.length === 1 ? organizations[0]?.id : undefined);
    if (selectedOrgId !== undefined) {
      if (!organizations.some(({ id }) => id === selectedOrgId)) throw new ApiError(403, "MEMBERSHIP_REQUIRED", "Active organization membership is required");
      await dependencies.database.switchActiveOrganization(session.sessionId, credentials.user.id, selectedOrgId);
    }
    return { data: {
      ...credentials,
      organizations: organizations.map((organization) => ({ ...organization, active: organization.id === selectedOrgId })),
      activeOrgId: selectedOrgId ?? null,
    } };
  });

  app.get("/api/v1/projects", {
    schema: { operationId: "listProjects", tags: ["projects"], querystring: searchablePageQuery, response: apiResponses(listSchema(projectSchema), true) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const all = await dependencies.projects.list(transaction, context.userId);
    const scoped = context.apiKey?.projectId === null || context.apiKey === null
      ? all
      : all.filter(({ id }) => id === context.apiKey?.projectId);
    const query = request.query as PageQuery;
    const terms = (query.search ?? "").trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    const visible = scoped.filter((project) => {
      if (query.tagId !== undefined && !project.tagIds.includes(query.tagId)) return false;
      const search = `${project.name} ${project.slug} ${project.description ?? ""} ${project.tags.map(({ name }) => name).join(" ")}`.toLocaleLowerCase();
      return terms.every((term) => search.includes(term));
    });
    return paginated(visible, request.query as PageQuery);
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

  app.get("/api/v1/projects/:projectId/consistency", {
    schema: {
      operationId: "getProjectConsistency",
      tags: ["consistency"],
      params: idParams({ projectId: uuid }),
      response: apiResponses(consistencyReportSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => ({
    data: await dependencies.consistency.compute(
      transaction,
      context.userId,
      params(request).projectId ?? "",
    ),
  })));

  registerEnvironmentRoutes(app, dependencies, withTenant);
  registerSecretRoutes(app, dependencies, withTenant);
  registerAuditRoutes(app, dependencies, withTenant);
  registerTagRoutes(app, withTenant);
  registerApiKeyRoutes(app, dependencies, withTenant);

  await app.ready();
  return app;
}

type WithTenant = <T>(
  request: FastifyRequest,
  work: (transaction: TenantTransaction, context: ApiRequestContext) => Promise<T>,
) => Promise<T>;

interface AuditQuery {
  actor?: string;
  action?: string;
  projectId?: string;
  environmentId?: string;
  from?: string;
  to?: string;
  resource?: string;
  cursor?: string;
  limit?: number;
}

function auditFilters(query: AuditQuery): AuditEventFilters {
  return {
    ...(query.actor === undefined ? {} : { actor: query.actor }),
    ...(query.action === undefined ? {} : { action: query.action }),
    ...(query.projectId === undefined ? {} : { projectId: query.projectId }),
    ...(query.environmentId === undefined ? {} : { environmentId: query.environmentId }),
    ...(query.from === undefined ? {} : { from: new Date(query.from) }),
    ...(query.to === undefined ? {} : { to: new Date(query.to) }),
    ...(query.resource === undefined ? {} : { resource: query.resource }),
    ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
    ...(query.limit === undefined ? {} : { limit: query.limit }),
  };
}

function registerAuditRoutes(
  app: FastifyInstance,
  dependencies: ApiDependencies,
  withTenant: WithTenant,
): void {
  app.get("/api/v1/audit-events", {
    schema: {
      operationId: "listAuditEvents", tags: ["audit"],
      querystring: { type: "object", additionalProperties: false, properties: {
        ...auditFilterProperties,
        cursor: { type: "string", maxLength: 1000 }, limit: { type: "integer", minimum: 1, maximum: 100, default: 50 },
      } },
      response: apiResponses(auditPageSchema),
    },
  }, async (request) => withTenant(request, async (transaction) => ({
    data: await dependencies.audit.list(transaction, transaction.orgId, auditFilters(request.query as AuditQuery)),
  })));
  app.get("/api/v1/audit-events/export", {
    schema: {
      operationId: "exportAuditEvents", tags: ["audit"],
      querystring: { type: "object", additionalProperties: false, required: ["format"], properties: {
        ...auditFilterProperties, format: { type: "string", enum: ["csv", "json"] },
      } },
      response: apiResponses(auditExportSchema),
    },
  }, async (request) => withTenant(request, async (transaction) => {
    const query = request.query as AuditQuery & { format: "csv" | "json" };
    return { data: await dependencies.audit.export(transaction, transaction.orgId, query.format, auditFilters(query)) };
  }));
  app.get("/api/v1/audit-settings", {
    schema: { operationId: "getAuditSettings", tags: ["audit"], response: apiResponses({
      type: "object", additionalProperties: false, required: ["retentionDays"], properties: { retentionDays: { type: "integer", minimum: 1, maximum: 3650 } },
    }) },
  }, async (request) => withTenant(request, async (transaction) => ({ data: {
    retentionDays: await dependencies.audit.getRetention(transaction, transaction.orgId),
  } })));
  app.patch("/api/v1/audit-settings", {
    schema: {
      operationId: "updateAuditSettings", tags: ["audit"],
      body: { type: "object", additionalProperties: false, required: ["retentionDays"], properties: { retentionDays: { type: "integer", minimum: 1, maximum: 3650 } } },
      response: apiResponses({ type: "object", additionalProperties: false, required: ["retentionDays"], properties: { retentionDays: { type: "integer" } } }),
    },
  }, async (request) => withTenant(request, async (transaction, context) => ({ data: {
    retentionDays: await dependencies.audit.updateRetention(
      transaction,
      transaction.orgId,
      context.userId,
      (request.body as { retentionDays: number }).retentionDays,
    ),
  } })));
}

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
    const visible = context.apiKey?.environmentId === null || context.apiKey === null
      ? all
      : all.filter(({ id }) => id === context.apiKey?.environmentId);
    return paginated(visible, request.query as PageQuery);
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
      tagIds: { type: "array", maxItems: 50, uniqueItems: true, items: uuid },
    },
  } as const;
  app.get("/api/v1/projects/:projectId/environments/:environmentId/secrets", {
    schema: { operationId: "listSecrets", tags: ["secrets"], params: scopeParams, querystring: searchablePageQuery, response: apiResponses(listSchema(secretMetadataSchema), true) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const query = request.query as PageQuery;
    const all = await dependencies.secrets.list(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      params(request).environmentId ?? "",
      { ...(query.search === undefined ? {} : { search: query.search }), ...(query.tagId === undefined ? {} : { tagId: query.tagId }) },
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
  app.get("/api/v1/projects/:projectId/environments/:environmentId/secrets/runtime", {
    schema: {
      operationId: "fetchRuntimeSecrets", tags: ["secrets"], params: scopeParams,
      response: {
        200: responseEnvelope(runtimeConfigSchema),
        304: { type: "null" },
        "4xx": errorResponse,
        "5xx": errorResponse,
      },
    },
  }, async (request, reply) => withTenant(request, async (transaction, context) => {
    const result = await dependencies.secrets.runtimeConfig(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      params(request).environmentId ?? "",
      parseRuntimeEtags(headerValue(request.headers["if-none-match"])),
      context.actor.type === "api_key"
        ? { type: "api_key", id: context.actor.apiKeyId }
        : { type: "user", id: context.actor.userId },
    );
    void reply.header("etag", runtimeEtag(result.configVersion));
    void reply.header("x-himitsu-config-version", String(result.configVersion));
    if (result.notModified) return reply.status(304).send();
    return reply.status(200).send({ data: {
      configVersion: result.configVersion,
      secrets: result.secrets ?? {},
    } });
  }));
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
    const values = [];
    for (const { id } of selected) {
      values.push(await dependencies.secrets.get(transaction, context.userId, id));
    }
    return { data: Object.fromEntries(values.map(({ key, value }) => [key, value])), meta: { count: values.length } };
  }));
  app.get("/api/v1/projects/:projectId/environments/:environmentId/exports", {
    schema: {
      operationId: "exportSecrets", tags: ["secrets"], params: scopeParams,
      querystring: {
        type: "object", additionalProperties: false, required: ["format"],
        properties: {
          format: { type: "string", enum: ["dotenv", "json", "shell"] },
          nested: { type: "boolean", default: false },
          delimiter: { type: "string", minLength: 1, maxLength: 10, default: "__" },
        },
      },
      response: apiResponses(secretExportSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const query = request.query as { format: "dotenv" | "json" | "shell"; nested?: boolean; delimiter?: string };
    return { data: await dependencies.secrets.exportConfig(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      params(request).environmentId ?? "",
      query.format,
      { nested: query.nested ?? false, delimiter: query.delimiter ?? "__" },
      context.actor.type === "api_key"
        ? { type: "api_key", id: context.actor.apiKeyId }
        : { type: "user", id: context.actor.userId },
    ) };
  }));
  const dotenvBody = {
    type: "object", additionalProperties: false, required: ["content"],
    properties: { content: { type: "string", minLength: 1, maxLength: 1_048_576 } },
  } as const;
  app.post("/api/v1/projects/:projectId/environments/:environmentId/imports/dotenv/preview", {
    schema: {
      operationId: "previewDotenvImport", tags: ["imports"], params: scopeParams,
      body: dotenvBody, response: apiResponses(dotenvPreviewSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const projectId = params(request).projectId ?? "";
    const environmentId = params(request).environmentId ?? "";
    const parsed = parseDotenv((request.body as { content: string }).content);
    const existing = await dependencies.secrets.list(transaction, context.userId, projectId, environmentId);
    return { data: buildDotenvPreview(parsed, new Set(existing.map(({ key }) => key))) };
  }));
  app.post("/api/v1/projects/:projectId/environments/:environmentId/imports/dotenv", {
    schema: {
      operationId: "commitDotenvImport", tags: ["imports"], params: scopeParams,
      body: {
        type: "object", additionalProperties: false, required: ["content", "strategy"],
        properties: {
          ...dotenvBody.properties,
          strategy: { type: "string", enum: ["skip", "overwrite", "merge"] },
          selectedKeys: { type: "array", maxItems: 100, uniqueItems: true, items: { type: "string" } },
        },
      },
      response: apiResponses(importResultSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const body = request.body as { content: string; strategy: "skip" | "overwrite" | "merge"; selectedKeys?: string[] };
    const parsed = parseDotenv(body.content);
    if (parsed.issues.length > 0) {
      throw new ApiError(400, "DOTENV_PARSE_ERROR", "Resolve dotenv conflicts before importing", { conflicts: parsed.issues });
    }
    const result = await dependencies.secrets.importBatch(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      params(request).environmentId ?? "",
      parsed.entries.map(({ key, value }) => ({
        key,
        value,
        ...(!/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/.test(key) ? { allowNonConformingKey: true } : {}),
      })),
      body.strategy,
      body.selectedKeys ?? [],
    );
    return { data: result };
  }));
  const jsonBody = {
    type: "object", additionalProperties: false, required: ["content"],
    properties: {
      content: { type: "string", minLength: 1, maxLength: 1_048_576 },
      delimiter: { type: "string", minLength: 1, maxLength: 10, default: "__" },
    },
  } as const;
  app.post("/api/v1/projects/:projectId/environments/:environmentId/imports/json/preview", {
    schema: {
      operationId: "previewJsonImport", tags: ["imports"], params: scopeParams,
      body: jsonBody, response: apiResponses(jsonImportPreviewSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const projectId = params(request).projectId ?? "";
    const environmentId = params(request).environmentId ?? "";
    const body = request.body as { content: string; delimiter?: string };
    const parsed = parseJsonSecrets(body.content, body.delimiter ?? "__");
    const existing = await dependencies.secrets.list(transaction, context.userId, projectId, environmentId);
    return { data: buildJsonImportPreview(parsed, new Set(existing.map(({ key }) => key))) };
  }));
  app.post("/api/v1/projects/:projectId/environments/:environmentId/imports/json", {
    schema: {
      operationId: "commitJsonImport", tags: ["imports"], params: scopeParams,
      body: {
        type: "object", additionalProperties: false, required: ["content", "strategy"],
        properties: {
          ...jsonBody.properties,
          strategy: { type: "string", enum: ["skip", "overwrite", "merge"] },
          selectedKeys: { type: "array", maxItems: 100, uniqueItems: true, items: { type: "string" } },
        },
      },
      response: apiResponses(importResultSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const body = request.body as { content: string; delimiter?: string; strategy: "skip" | "overwrite" | "merge"; selectedKeys?: string[] };
    const parsed = parseJsonSecrets(body.content, body.delimiter ?? "__");
    if (parsed.issues.length > 0) {
      throw new ApiError(400, "JSON_IMPORT_ERROR", "Resolve JSON conflicts before importing", { conflicts: parsed.issues });
    }
    const result = await dependencies.secrets.importBatch(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      params(request).environmentId ?? "",
      parsed.entries.map(({ key, value }) => ({
        key,
        value,
        ...(!/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/.test(key) ? { allowNonConformingKey: true } : {}),
      })),
      body.strategy,
      body.selectedKeys ?? [],
      "json",
    );
    return { data: result };
  }));
  const promotionBody = {
    type: "object", additionalProperties: false, required: ["sourceEnvironmentId"],
    properties: {
      sourceEnvironmentId: uuid,
      keys: { type: "array", minItems: 1, maxItems: 100, uniqueItems: true, items: { type: "string", minLength: 1, maxLength: 255 } },
    },
  } as const;
  app.post("/api/v1/projects/:projectId/environments/:environmentId/promotions/preview", {
    schema: {
      operationId: "previewSecretPromotion", tags: ["secrets"], params: scopeParams,
      body: promotionBody, response: apiResponses(promotionPreviewSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const body = request.body as { sourceEnvironmentId: string; keys?: string[] };
    return { data: await dependencies.secrets.previewPromotion(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      body.sourceEnvironmentId,
      params(request).environmentId ?? "",
      body.keys,
    ) };
  }));
  app.post("/api/v1/projects/:projectId/environments/:environmentId/promotions", {
    schema: {
      operationId: "promoteSecrets", tags: ["secrets"], params: scopeParams,
      body: promotionBody, response: apiResponses(promotionResultSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const body = request.body as { sourceEnvironmentId: string; keys?: string[] };
    return { data: await dependencies.secrets.promote(
      transaction,
      context.userId,
      params(request).projectId ?? "",
      body.sourceEnvironmentId,
      params(request).environmentId ?? "",
      body.keys,
    ) };
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
      body: { type: "object", additionalProperties: false, required: ["value"], properties: { value: { type: "string" }, notes: { type: ["string", "null"], maxLength: 4000 }, changeNote: { type: ["string", "null"], maxLength: 1000 }, tagIds: { type: "array", maxItems: 50, uniqueItems: true, items: uuid } } },
      response: apiResponses(secretMetadataSchema),
    },
  }, async (request) => {
    const header = request.headers["if-match"];
    const match = typeof header === "string" ? /^(?:W\/)?\"?(\d+)\"?$/.exec(header.trim()) : null;
    if (header !== undefined && match?.[1] === undefined) {
      throw new ApiError(400, "INVALID_IF_MATCH", "If-Match must contain a numeric secret version");
    }
    const expectedVersion = match?.[1] === undefined ? undefined : Number(match[1]);
    return withTenant(request, async (transaction, context) => ({ data: await dependencies.secrets.update(
      transaction,
      context.userId,
      params(request).secretId ?? "",
      {
        ...(request.body as Parameters<SecretService["update"]>[3]),
        ...(expectedVersion === undefined ? {} : { expectedVersion }),
      },
    ) }));
  });
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
  app.get("/api/v1/secrets/:secretId/versions/compare", {
    schema: {
      operationId: "compareSecretVersions", tags: ["versions"], params: secretParams,
      querystring: {
        type: "object", additionalProperties: false, required: ["from", "to"],
        properties: { from: { type: "integer", minimum: 1 }, to: { type: "integer", minimum: 1 }, reveal: { type: "boolean", default: false } },
      },
      response: apiResponses(versionComparisonSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const query = request.query as { from: number; to: number; reveal?: boolean };
    return { data: await dependencies.secrets.compareVersions(
      transaction,
      context.userId,
      params(request).secretId ?? "",
      query.from,
      query.to,
      query.reveal ?? false,
    ) };
  }));
  app.post("/api/v1/secrets/:secretId/versions/:version/rollback", {
    schema: {
      operationId: "rollbackSecretVersion", tags: ["versions"],
      params: idParams({ secretId: uuid, version: { type: "integer", minimum: 1 } }),
      body: {
        type: "object", additionalProperties: false,
        properties: { expectedVersion: { type: "integer", minimum: 1 }, changeNote: { type: ["string", "null"], maxLength: 1000 } },
      },
      response: apiResponses(secretMetadataSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const routeParams = request.params as { secretId: string; version: number };
    return { data: await dependencies.secrets.rollback(
      transaction,
      context.userId,
      routeParams.secretId,
      routeParams.version,
      request.body as Parameters<SecretService["rollback"]>[4],
    ) };
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
  app.post("/api/v1/tags/:tagId/merge", {
    schema: {
      operationId: "mergeTag", tags: ["tags"], params: idParams({ tagId: uuid }),
      body: { type: "object", additionalProperties: false, required: ["targetTagId"], properties: { targetTagId: uuid } },
      response: apiResponses(tagSchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => {
    requirePermission(await resolver.resolve(transaction, context.userId), "org.settings.update");
    const sourceTagId = params(request).tagId ?? "";
    const { targetTagId } = request.body as { targetTagId: string };
    if (sourceTagId === targetTagId) throw new ApiError(400, "INVALID_INPUT", "A tag cannot be merged into itself");
    const locked = await transaction.query<TagRow>(
      `SELECT id, name, color, created_at, updated_at FROM tags
       WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE`,
      [[sourceTagId, targetTagId]],
    );
    if (locked.rowCount !== 2) throw new ApiError(404, "NOT_FOUND", "Source or target tag not found");
    await transaction.query(
      `INSERT INTO project_tags (org_id, project_id, tag_id)
       SELECT org_id, project_id, $2 FROM project_tags WHERE tag_id = $1
       ON CONFLICT (org_id, project_id, tag_id) DO NOTHING`,
      [sourceTagId, targetTagId],
    );
    await transaction.query(
      `INSERT INTO secret_tags (org_id, project_id, environment_id, secret_id, tag_id)
       SELECT org_id, project_id, environment_id, secret_id, $2 FROM secret_tags WHERE tag_id = $1
       ON CONFLICT (org_id, secret_id, tag_id) DO NOTHING`,
      [sourceTagId, targetTagId],
    );
    await transaction.query("DELETE FROM tags WHERE id = $1", [sourceTagId]);
    const target = locked.rows.find(({ id }) => id === targetTagId);
    if (target === undefined) throw new ApiError(404, "NOT_FOUND", "Target tag not found");
    return { data: tagFromRow(target) };
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

function registerApiKeyRoutes(
  app: FastifyInstance,
  dependencies: ApiDependencies,
  withTenant: WithTenant,
): void {
  app.get("/api/v1/api-keys", {
    schema: { operationId: "listApiKeys", tags: ["api-keys"], querystring: pageQuery, response: apiResponses(listSchema(apiKeySchema), true) },
  }, async (request) => withTenant(request, async (transaction, context) => {
    const all = await dependencies.apiKeys.list(transaction, context.userId);
    return paginated(all, request.query as PageQuery);
  }));
  app.post("/api/v1/api-keys", {
    schema: {
      operationId: "createApiKey", tags: ["api-keys"],
      body: {
        type: "object", additionalProperties: false, required: ["name", "access"],
        properties: {
          name: { type: "string", minLength: 1, maxLength: 120 },
          access: { type: "string", enum: ["read_only", "read_write"] },
          projectId: nullableUuid, environmentId: nullableUuid,
          expiresAt: { type: ["string", "null"], format: "date-time" },
        },
      },
      response: apiResponses(createdApiKeySchema),
    },
  }, async (request, reply) => {
    const body = request.body as {
      name: string;
      access: "read_only" | "read_write";
      projectId?: string | null;
      environmentId?: string | null;
      expiresAt?: string | null;
    };
    const created = await withTenant(request, (transaction, context) => dependencies.apiKeys.create(
      transaction,
      context.userId,
      {
        name: body.name,
        access: body.access,
        ...(body.projectId === undefined ? {} : { projectId: body.projectId }),
        ...(body.environmentId === undefined ? {} : { environmentId: body.environmentId }),
        ...(body.expiresAt === undefined
          ? {}
          : { expiresAt: body.expiresAt === null ? null : new Date(body.expiresAt) }),
      },
    ));
    return reply.status(201).send({ data: created });
  });
  app.delete("/api/v1/api-keys/:apiKeyId", {
    schema: {
      operationId: "revokeApiKey", tags: ["api-keys"], params: idParams({ apiKeyId: uuid }),
      response: apiResponses(apiKeySchema),
    },
  }, async (request) => withTenant(request, async (transaction, context) => ({ data: await dependencies.apiKeys.revoke(
    transaction,
    context.userId,
    params(request).apiKeyId ?? "",
  ) })));
}

function params(request: FastifyRequest): IdParams {
  return request.params as IdParams;
}

function isReadOperation(request: FastifyRequest): boolean {
  return request.method === "GET"
    || request.method === "HEAD"
    || routePath(request).endsWith("/secrets/bulk-get");
}

function routePath(request: FastifyRequest): string {
  return request.routeOptions.url ?? request.url.split("?", 1)[0] ?? "";
}

function routeOperationId(request: FastifyRequest): string | undefined {
  return (request.routeOptions.schema as { operationId?: string } | undefined)?.operationId;
}

async function enforceRoutePermission(
  request: FastifyRequest,
  transaction: TenantTransaction,
  context: ApiRequestContext,
  resolver: AuthorizationContextResolver,
): Promise<void> {
  const operationId = routeOperationId(request);
  const permission = operationId === undefined ? undefined : apiRoutePermissions[operationId as keyof typeof apiRoutePermissions];
  if (permission === undefined) {
    throw new ApiError(500, "AUTHORIZATION_POLICY_MISSING", "Route authorization policy is missing");
  }
  const requestParams = params(request);
  let projectId = requestParams.projectId;
  let protectedEnvironment = false;
  if (requestParams.secretId !== undefined) {
    const secret = await transaction.query<{ project_id: string; protected: boolean }>(
      `SELECT secret.project_id, environment.protected
       FROM secrets secret
       JOIN environments environment ON environment.id = secret.environment_id
       WHERE secret.id = $1 AND secret.deleted_at IS NULL AND environment.deleted_at IS NULL`,
      [requestParams.secretId],
    );
    projectId = secret.rows[0]?.project_id;
    protectedEnvironment = secret.rows[0]?.protected ?? false;
  } else if (requestParams.environmentId !== undefined) {
    const environment = await transaction.query<{ project_id: string; protected: boolean }>(
      "SELECT project_id, protected FROM environments WHERE id = $1 AND deleted_at IS NULL",
      [requestParams.environmentId],
    );
    projectId = environment.rows[0]?.project_id ?? projectId;
    protectedEnvironment = environment.rows[0]?.protected ?? false;
  } else if (operationId === "createApiKey") {
    const body = request.body as { projectId?: string | null; environmentId?: string | null };
    projectId = body.projectId ?? undefined;
    if (body.environmentId !== null && body.environmentId !== undefined) {
      const environment = await transaction.query<{ project_id: string; protected: boolean }>(
        "SELECT project_id, protected FROM environments WHERE id = $1 AND deleted_at IS NULL",
        [body.environmentId],
      );
      projectId = environment.rows[0]?.project_id ?? projectId;
      protectedEnvironment = environment.rows[0]?.protected ?? false;
    }
  }
  requirePermission(
    await resolver.resolve(transaction, context.userId, projectId, protectedEnvironment),
    permission,
  );
}

async function enforceApiKeyScope(
  request: FastifyRequest,
  transaction: TenantTransaction,
  context: ApiRequestContext,
): Promise<void> {
  const principal = context.apiKey;
  if (principal === null) return;
  if (principal.access === "read_only" && !isReadOperation(request)) {
    throw new ApiError(403, "API_SCOPE_FORBIDDEN", "API key does not permit writes");
  }
  if (principal.projectId === null) return;
  const route = routePath(request);
  if (route.startsWith("/api/v1/tags") || route.startsWith("/api/v1/api-keys") || route.startsWith("/api/v1/audit")) {
    throw new ApiError(403, "API_SCOPE_FORBIDDEN", "API key scope does not include organization resources");
  }
  const requestParams = params(request);
  if (requestParams.projectId !== undefined && requestParams.projectId !== principal.projectId) {
    throw new ApiError(403, "API_SCOPE_FORBIDDEN", "API key project scope does not match this request");
  }
  if (
    principal.environmentId !== null
    && requestParams.environmentId !== undefined
    && requestParams.environmentId !== principal.environmentId
  ) {
    throw new ApiError(403, "API_SCOPE_FORBIDDEN", "API key environment scope does not match this request");
  }
  if (
    principal.environmentId !== null
    && (routeOperationId(request) === "previewSecretPromotion" || routeOperationId(request) === "promoteSecrets")
    && (request.body as { sourceEnvironmentId?: string }).sourceEnvironmentId !== principal.environmentId
  ) {
    throw new ApiError(403, "API_SCOPE_FORBIDDEN", "API key environment scope does not include the promotion source");
  }
  if (requestParams.secretId !== undefined) {
    const secret = await transaction.query<{ project_id: string; environment_id: string }>(
      "SELECT project_id, environment_id FROM secrets WHERE id = $1 AND deleted_at IS NULL",
      [requestParams.secretId],
    );
    const scope = secret.rows[0];
    if (
      scope !== undefined
      && (scope.project_id !== principal.projectId
        || (principal.environmentId !== null && scope.environment_id !== principal.environmentId))
    ) {
      throw new ApiError(403, "API_SCOPE_FORBIDDEN", "API key scope does not include this secret");
    }
    return;
  }
  if (route === "/api/v1/projects" && request.method === "GET") return;
  if (requestParams.projectId === undefined) {
    throw new ApiError(403, "API_SCOPE_FORBIDDEN", "API key scope does not include this resource");
  }
  if (
    principal.environmentId !== null
    && requestParams.environmentId === undefined
    && isUnsafeMethod(request.method)
  ) {
    throw new ApiError(403, "API_SCOPE_FORBIDDEN", "Environment-scoped API keys cannot modify project-wide resources");
  }
}

function pagination(query: PageQuery): { limit: number; offset: number } {
  return { limit: query.limit ?? 50, offset: query.offset ?? 0 };
}

function runtimeEtag(configVersion: number): string {
  return `"himi-config-${configVersion}"`;
}

function parseRuntimeEtags(header: string | undefined): readonly number[] | "*" {
  if (header === undefined) return [];
  const tags = header.split(",").map((value) => value.trim());
  if (tags.includes("*")) return "*";
  return tags.flatMap((tag) => {
    const match = /^(?:W\/)?"himi-config-(\d+)"$/.exec(tag);
    if (match?.[1] === undefined) return [];
    const version = Number(match[1]);
    return Number.isSafeInteger(version) ? [version] : [];
  });
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
  if (error instanceof AuthError) {
    if (error.code === "INVALID_CSRF") return new ApiError(403, "INVALID_CSRF", "CSRF validation failed");
    if (error.code === "RATE_LIMITED") return new ApiError(429, "RATE_LIMITED", "Too many authentication attempts");
    return new ApiError(401, "UNAUTHENTICATED", "Session is invalid or expired");
  }
  if (error instanceof ProjectError || error instanceof EnvironmentError || error instanceof SecretError || error instanceof ConsistencyError || error instanceof AuditError) {
    if (error.code === "NOT_FOUND" || error.code === "VERSION_NOT_FOUND") return new ApiError(404, error.code, error.message);
    if (error.code.endsWith("EXISTS") || error.code === "VERSION_CONFLICT") return new ApiError(409, error.code, error.message);
    return new ApiError(400, error.code, error.message);
  }
  if (error instanceof ApiKeyError) {
    if (error.code === "NOT_FOUND") return new ApiError(404, "NOT_FOUND", error.message);
    if (error.code === "INVALID_TOKEN") return new ApiError(401, "UNAUTHENTICATED", "API token is invalid");
    return new ApiError(400, error.code, error.message);
  }
  if (error instanceof TenancyError) {
    if (error.code === "MEMBERSHIP_REQUIRED") return new ApiError(403, "FORBIDDEN", "Active organization membership is required");
    return new ApiError(400, error.code, error.message);
  }
  if ((error as { code?: string }).code === "23505") return new ApiError(409, "CONFLICT", "Resource already exists");
  return new ApiError(500, "INTERNAL_ERROR", "An unexpected error occurred");
}
