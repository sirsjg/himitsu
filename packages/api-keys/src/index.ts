import { createHash, randomBytes } from "node:crypto";
import type { AuditEventInput, AuditTransaction, TransactionalAuditLog } from "@himitsu/audit";
import { AuthorizationContextResolver, requirePermission } from "@himitsu/authz";
import type { TenantTransaction } from "@himitsu/tenancy";
import type { Pool } from "pg";

export type ApiKeyAccess = "read_only" | "read_write";

export class ApiKeyError extends Error {
  readonly code: "INVALID_INPUT" | "NOT_FOUND" | "INVALID_TOKEN";

  constructor(code: ApiKeyError["code"], message: string) {
    super(message);
    this.name = "ApiKeyError";
    this.code = code;
  }
}

export interface ApiKey {
  readonly id: string;
  readonly orgId: string;
  readonly projectId: string | null;
  readonly environmentId: string | null;
  readonly name: string;
  readonly prefix: string;
  readonly access: ApiKeyAccess;
  readonly createdAt: Date;
  readonly expiresAt: Date | null;
  readonly lastUsedAt: Date | null;
  readonly revokedAt: Date | null;
}

export interface CreatedApiKey {
  readonly apiKey: ApiKey;
  readonly token: string;
}

export interface ApiKeyPrincipal {
  readonly apiKeyId: string;
  readonly orgId: string;
  readonly userId: string;
  readonly projectId: string | null;
  readonly environmentId: string | null;
  readonly access: ApiKeyAccess;
  readonly prefix: string;
  readonly usedAt: Date;
}

interface ApiKeyRow {
  id: string;
  org_id: string;
  project_id: string | null;
  environment_id: string | null;
  name: string;
  prefix: string;
  access: ApiKeyAccess;
  created_at: Date;
  expires_at: Date | null;
  last_used_at: Date | null;
  revoked_at: Date | null;
}

interface ConsumedApiKeyRow {
  id: string;
  org_id: string;
  project_id: string | null;
  environment_id: string | null;
  created_by_user_id: string;
  prefix: string;
  access: ApiKeyAccess;
  last_used_at: Date;
}

interface ApiKeyIdentityRow {
  id: string;
  org_id: string;
  project_id: string | null;
  environment_id: string | null;
}

interface AuditRecorder {
  recordInTransaction(transaction: AuditTransaction, event: AuditEventInput): Promise<void>;
}

const apiKeySelect = `SELECT id, org_id, project_id, environment_id, name, prefix, access,
  created_at, expires_at, last_used_at, revoked_at FROM api_keys`;

export function tokenPrefix(token: string): string {
  const match = /^(himi_[0-9a-f]{16})_[A-Za-z0-9_-]{43}$/.exec(token);
  if (match?.[1] === undefined) throw new ApiKeyError("INVALID_TOKEN", "API token is invalid");
  return match[1];
}

function tokenDigest(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

function apiKeyName(name: string): string {
  const normalized = name.trim();
  if (normalized.length < 1 || normalized.length > 120) {
    throw new ApiKeyError("INVALID_INPUT", "API key name must be between 1 and 120 characters");
  }
  return normalized;
}

function expiry(value: Date | null | undefined, now: Date): Date | null {
  if (value === null || value === undefined) return null;
  if (!Number.isFinite(value.getTime()) || value.getTime() <= now.getTime()) {
    throw new ApiKeyError("INVALID_INPUT", "API key expiry must be in the future");
  }
  return value;
}

function fromRow(row: ApiKeyRow): ApiKey {
  return {
    id: row.id,
    orgId: row.org_id,
    projectId: row.project_id,
    environmentId: row.environment_id,
    name: row.name,
    prefix: row.prefix,
    access: row.access,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at,
  };
}

export class ApiKeyService {
  readonly #pool: Pool;
  readonly #resolver: AuthorizationContextResolver;
  readonly #audit: AuditRecorder;
  readonly #now: () => Date;

  constructor(
    pool: Pool,
    resolver: AuthorizationContextResolver,
    audit: TransactionalAuditLog,
    options: { now?: () => Date } = {},
  ) {
    this.#pool = pool;
    this.#resolver = resolver;
    this.#audit = audit;
    this.#now = options.now ?? (() => new Date());
  }

  async list(transaction: TenantTransaction, actorUserId: string): Promise<readonly ApiKey[]> {
    requirePermission(await this.#resolver.resolve(transaction, actorUserId), "api_key.read");
    const result = await transaction.query<ApiKeyRow>(`${apiKeySelect} ORDER BY created_at DESC, id`);
    return result.rows.map(fromRow);
  }

  async create(
    transaction: TenantTransaction,
    actorUserId: string,
    input: {
      name: string;
      access: ApiKeyAccess;
      projectId?: string | null;
      environmentId?: string | null;
      expiresAt?: Date | null;
    },
  ): Promise<CreatedApiKey> {
    const projectId = input.projectId ?? null;
    const environmentId = input.environmentId ?? null;
    if (environmentId !== null && projectId === null) {
      throw new ApiKeyError("INVALID_INPUT", "Environment-scoped API keys require a project");
    }
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId ?? undefined),
      "api_key.create",
    );
    await this.#validateScope(transaction, projectId, environmentId);
    const now = this.#now();
    const expiresAt = expiry(input.expiresAt, now);
    const prefix = `himi_${randomBytes(8).toString("hex")}`;
    const token = `${prefix}_${randomBytes(32).toString("base64url")}`;
    const digest = tokenDigest(token);
    try {
      const inserted = await transaction.query<ApiKeyRow>(
        `INSERT INTO api_keys
          (org_id, project_id, environment_id, name, prefix, token_hash, access,
           created_by_user_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id, org_id, project_id, environment_id, name, prefix, access,
                   created_at, expires_at, last_used_at, revoked_at`,
        [
          transaction.orgId,
          projectId,
          environmentId,
          apiKeyName(input.name),
          prefix,
          digest,
          input.access,
          actorUserId,
          expiresAt,
        ],
      );
      const row = inserted.rows[0];
      if (row === undefined) throw new Error("API key insertion returned no row");
      const apiKey = fromRow(row);
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: { type: "user", id: actorUserId },
        action: "api_key.created",
        resource: { type: "api_key", id: apiKey.id },
        ...(projectId === null ? {} : { projectId }),
        ...(environmentId === null ? {} : { environmentId }),
        after: {
          access: apiKey.access,
          scope: environmentId === null ? (projectId === null ? "organization" : "project") : "environment",
          expiresAt: expiresAt?.toISOString() ?? null,
        },
      });
      return { apiKey, token };
    } finally {
      digest.fill(0);
    }
  }

  async revoke(
    transaction: TenantTransaction,
    actorUserId: string,
    apiKeyId: string,
  ): Promise<ApiKey> {
    const existing = await transaction.query<ApiKeyRow>(
      `${apiKeySelect} WHERE id = $1 FOR UPDATE`,
      [apiKeyId],
    );
    const row = existing.rows[0];
    if (row === undefined) throw new ApiKeyError("NOT_FOUND", "API key not found");
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, row.project_id ?? undefined),
      "api_key.revoke",
    );
    if (row.revoked_at !== null) return fromRow(row);
    const updated = await transaction.query<ApiKeyRow>(
      `UPDATE api_keys SET revoked_at = now() WHERE id = $1
       RETURNING id, org_id, project_id, environment_id, name, prefix, access,
                 created_at, expires_at, last_used_at, revoked_at`,
      [apiKeyId],
    );
    const revoked = updated.rows[0];
    if (revoked === undefined) throw new ApiKeyError("NOT_FOUND", "API key not found");
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "api_key.revoked",
      resource: { type: "api_key", id: apiKeyId },
      ...(row.project_id === null ? {} : { projectId: row.project_id }),
      ...(row.environment_id === null ? {} : { environmentId: row.environment_id }),
      before: { access: row.access, revoked: false },
      after: { access: row.access, revoked: true },
    });
    return fromRow(revoked);
  }

  async authenticate(
    token: string,
    request: { ip?: string; userAgent?: string } = {},
  ): Promise<ApiKeyPrincipal> {
    const prefix = tokenPrefix(token);
    const digest = tokenDigest(token);
    const client = await this.#pool.connect();
    let transactionFinished = false;
    try {
      await client.query("BEGIN");
      const consumed = await client.query<ConsumedApiKeyRow>(
        `SELECT id, org_id, project_id, environment_id, created_by_user_id,
                prefix, access, last_used_at
         FROM consume_api_key($1, $2)`,
        [prefix, digest],
      );
      const row = consumed.rows[0];
      if (row === undefined) {
        const identity = await client.query<ApiKeyIdentityRow>(
          `SELECT id, org_id, project_id, environment_id
           FROM resolve_api_key_identity($1)`,
          [prefix],
        );
        const identifiable = identity.rows[0];
        if (identifiable !== undefined) {
          await client.query("SELECT set_config('app.current_org_id', $1, true)", [identifiable.org_id]);
          await this.#audit.recordInTransaction(client, {
            orgId: identifiable.org_id,
            actor: { type: "api_key", id: identifiable.id },
            action: "auth.login_failed",
            resource: { type: "api_key", id: identifiable.id },
            ...(identifiable.project_id === null ? {} : { projectId: identifiable.project_id }),
            ...(identifiable.environment_id === null ? {} : { environmentId: identifiable.environment_id }),
            ...(request.ip === undefined ? {} : { ip: request.ip }),
            ...(request.userAgent === undefined ? {} : { userAgent: request.userAgent }),
            details: { method: "bearer", reason: "invalid_or_inactive" },
          });
          await client.query("COMMIT");
          transactionFinished = true;
        }
        throw new ApiKeyError("INVALID_TOKEN", "API token is invalid");
      }
      await client.query("SELECT set_config('app.current_org_id', $1, true)", [row.org_id]);
      await this.#audit.recordInTransaction(client, {
        orgId: row.org_id,
        actor: { type: "api_key", id: row.id },
        action: "api_key.used",
        resource: { type: "api_key", id: row.id },
        ...(row.project_id === null ? {} : { projectId: row.project_id }),
        ...(row.environment_id === null ? {} : { environmentId: row.environment_id }),
        ...(request.ip === undefined ? {} : { ip: request.ip }),
        ...(request.userAgent === undefined ? {} : { userAgent: request.userAgent }),
        details: { access: row.access },
      });
      await client.query("COMMIT");
      transactionFinished = true;
      return {
        apiKeyId: row.id,
        orgId: row.org_id,
        userId: row.created_by_user_id,
        projectId: row.project_id,
        environmentId: row.environment_id,
        access: row.access,
        prefix: row.prefix,
        usedAt: row.last_used_at,
      };
    } catch (error) {
      if (!transactionFinished) await client.query("ROLLBACK");
      if (error instanceof ApiKeyError) throw error;
      throw new ApiKeyError("INVALID_TOKEN", "API token is invalid");
    } finally {
      digest.fill(0);
      client.release();
    }
  }

  async #validateScope(
    transaction: TenantTransaction,
    projectId: string | null,
    environmentId: string | null,
  ): Promise<void> {
    if (projectId === null) return;
    const scope = await transaction.query(
      `SELECT 1
       FROM projects p
       LEFT JOIN environments e
         ON e.project_id = p.id AND e.id = $2 AND e.deleted_at IS NULL
       WHERE p.id = $1 AND p.deleted_at IS NULL
         AND ($2::uuid IS NULL OR e.id IS NOT NULL)`,
      [projectId, environmentId],
    );
    if (scope.rowCount !== 1) throw new ApiKeyError("NOT_FOUND", "API key scope not found");
  }
}
