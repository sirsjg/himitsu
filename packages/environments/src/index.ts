import type { AuditEventInput, AuditTransaction, TransactionalAuditLog } from "@himitsu/audit";
import { AuthorizationContextResolver, requirePermission } from "@himitsu/authz";
import type { TenantTransaction } from "@himitsu/tenancy";

const DEFAULT_RECOVERY_DAYS = 30;
const MAX_ENVIRONMENTS = 50;

export class EnvironmentError extends Error {
  readonly code:
    | "INVALID_INPUT"
    | "SLUG_EXISTS"
    | "NOT_FOUND"
    | "LAST_ENVIRONMENT"
    | "SECRETS_REQUIRE_CONFIRMATION"
    | "ORDER_MISMATCH"
    | "RECOVERY_EXPIRED";

  constructor(code: EnvironmentError["code"], message: string) {
    super(message);
    this.name = "EnvironmentError";
    this.code = code;
  }
}

export interface Environment {
  readonly id: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly name: string;
  readonly slug: string;
  readonly displayOrder: number;
  readonly protected: boolean;
  readonly deletedAt: Date | null;
  readonly purgeAfter: Date | null;
}

interface EnvironmentRow {
  id: string;
  org_id: string;
  project_id: string;
  name: string;
  slug: string;
  display_order: number;
  protected: boolean;
  deleted_at: Date | null;
  purge_after: Date | null;
  deleted_by_project_at: Date | null;
}

interface AuditRecorder {
  recordInTransaction(transaction: AuditTransaction, event: AuditEventInput): Promise<void>;
}

export function normalizeEnvironmentSlug(slug: string): string {
  const normalized = slug.trim().toLowerCase();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(normalized) || normalized.length > 80) {
    throw new EnvironmentError(
      "INVALID_INPUT",
      "Environment slug must use lowercase words separated by hyphens",
    );
  }
  return normalized;
}

export function validateEnvironmentName(name: string): string {
  const normalized = name.trim();
  if (normalized.length < 1 || normalized.length > 80) {
    throw new EnvironmentError("INVALID_INPUT", "Environment name must be between 1 and 80 characters");
  }
  return normalized;
}

function fromRow(row: EnvironmentRow): Environment {
  return {
    id: row.id,
    orgId: row.org_id,
    projectId: row.project_id,
    name: row.name,
    slug: row.slug,
    displayOrder: row.display_order,
    protected: row.protected,
    deletedAt: row.deleted_at,
    purgeAfter: row.purge_after,
  };
}

export class EnvironmentService {
  readonly #resolver: AuthorizationContextResolver;
  readonly #audit: AuditRecorder;
  readonly #now: () => Date;
  readonly #recoveryMs: number;

  constructor(
    resolver: AuthorizationContextResolver,
    audit: TransactionalAuditLog,
    options: { now?: () => Date; recoveryDays?: number } = {},
  ) {
    this.#resolver = resolver;
    this.#audit = audit;
    this.#now = options.now ?? (() => new Date());
    const recoveryDays = options.recoveryDays ?? DEFAULT_RECOVERY_DAYS;
    if (!Number.isSafeInteger(recoveryDays) || recoveryDays < 1 || recoveryDays > 365) {
      throw new EnvironmentError("INVALID_INPUT", "Recovery days must be between 1 and 365");
    }
    this.#recoveryMs = recoveryDays * 24 * 60 * 60 * 1000;
  }

  async list(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
  ): Promise<readonly Environment[]> {
    await this.#requireActiveProject(transaction, projectId);
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, projectId), "environment.read");
    const result = await transaction.query<EnvironmentRow>(
      `SELECT id, org_id, project_id, name, slug, display_order, protected,
              deleted_at, purge_after, deleted_by_project_at
       FROM environments
       WHERE project_id = $1 AND deleted_at IS NULL
       ORDER BY display_order, id`,
      [projectId],
    );
    return result.rows.map(fromRow);
  }

  async get(
    transaction: TenantTransaction,
    actorUserId: string,
    environmentId: string,
    includeDeleted = false,
  ): Promise<Environment> {
    return this.#get(transaction, actorUserId, environmentId, includeDeleted);
  }

  async create(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    input: { name: string; slug: string; protected?: boolean },
  ): Promise<Environment> {
    await this.#requireActiveProject(transaction, projectId);
    const isProtected = input.protected ?? false;
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId, isProtected),
      "environment.create",
    );
    const count = await transaction.query<{ count: string }>(
      "SELECT count(*)::text AS count FROM environments WHERE project_id = $1 AND deleted_at IS NULL",
      [projectId],
    );
    if (Number(count.rows[0]?.count ?? 0) >= MAX_ENVIRONMENTS) {
      throw new EnvironmentError("INVALID_INPUT", `A project can have at most ${MAX_ENVIRONMENTS} environments`);
    }
    try {
      const inserted = await transaction.query<EnvironmentRow>(
        `INSERT INTO environments (org_id, project_id, name, slug, display_order, protected)
         SELECT $1, $2, $3, $4, COALESCE(max(display_order) + 1, 0), $5
         FROM environments WHERE project_id = $2 AND deleted_at IS NULL
         RETURNING id, org_id, project_id, name, slug, display_order, protected,
                   deleted_at, purge_after, deleted_by_project_at`,
        [
          transaction.orgId,
          projectId,
          validateEnvironmentName(input.name),
          normalizeEnvironmentSlug(input.slug),
          isProtected,
        ],
      );
      const row = inserted.rows[0];
      if (row === undefined) throw new Error("Environment insertion returned no row");
      const environment = fromRow(row);
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: { type: "user", id: actorUserId },
        action: "environment.created",
        resource: { type: "environment", id: environment.id },
        projectId,
        environmentId: environment.id,
        after: { name: environment.name, slug: environment.slug, protected: environment.protected },
      });
      return environment;
    } catch (error) {
      if ((error as { code?: string }).code === "23505") {
        throw new EnvironmentError("SLUG_EXISTS", "Environment slug is already in use in this project");
      }
      throw error;
    }
  }

  async update(
    transaction: TenantTransaction,
    actorUserId: string,
    environmentId: string,
    input: { name?: string; slug?: string; protected?: boolean },
  ): Promise<Environment> {
    const before = await this.#get(transaction, actorUserId, environmentId);
    const protectedWrite = before.protected || input.protected === true;
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, before.projectId, protectedWrite),
      "environment.update",
    );
    const name = input.name === undefined ? before.name : validateEnvironmentName(input.name);
    const slug = input.slug === undefined ? before.slug : normalizeEnvironmentSlug(input.slug);
    const isProtected = input.protected ?? before.protected;
    try {
      const result = await transaction.query<EnvironmentRow>(
        `UPDATE environments SET name = $1, slug = $2, protected = $3, updated_at = now()
         WHERE id = $4 AND deleted_at IS NULL
         RETURNING id, org_id, project_id, name, slug, display_order, protected,
                   deleted_at, purge_after, deleted_by_project_at`,
        [name, slug, isProtected, environmentId],
      );
      const row = result.rows[0];
      if (row === undefined) throw new EnvironmentError("NOT_FOUND", "Environment not found");
      const after = fromRow(row);
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: { type: "user", id: actorUserId },
        action: "environment.updated",
        resource: { type: "environment", id: environmentId },
        projectId: before.projectId,
        environmentId,
        before: { name: before.name, slug: before.slug, protected: before.protected },
        after: { name: after.name, slug: after.slug, protected: after.protected },
      });
      return after;
    } catch (error) {
      if ((error as { code?: string }).code === "23505") {
        throw new EnvironmentError("SLUG_EXISTS", "Environment slug is already in use in this project");
      }
      throw error;
    }
  }

  async reorder(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    environmentIds: readonly string[],
  ): Promise<readonly Environment[]> {
    await this.#requireActiveProject(transaction, projectId);
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, projectId), "environment.update");
    if (new Set(environmentIds).size !== environmentIds.length) {
      throw new EnvironmentError("ORDER_MISMATCH", "Environment order contains duplicate ids");
    }
    const current = await transaction.query<{ id: string; protected: boolean }>(
      "SELECT id, protected FROM environments WHERE project_id = $1 AND deleted_at IS NULL ORDER BY id",
      [projectId],
    );
    if (
      current.rowCount !== environmentIds.length
      || current.rows.some(({ id }) => !environmentIds.includes(id))
    ) {
      throw new EnvironmentError("ORDER_MISMATCH", "Environment order must contain every active environment exactly once");
    }
    if (current.rows.some(({ protected: isProtected }) => isProtected)) {
      requirePermission(
        await this.#resolver.resolve(transaction, actorUserId, projectId, true),
        "environment.update",
      );
    }
    await transaction.query(
      `UPDATE environments e SET display_order = ordered.display_order - 1, updated_at = now()
       FROM unnest($1::uuid[]) WITH ORDINALITY AS ordered(id, display_order)
       WHERE e.id = ordered.id AND e.project_id = $2 AND e.deleted_at IS NULL`,
      [environmentIds, projectId],
    );
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "environment.reordered",
      resource: { type: "project", id: projectId },
      projectId,
      after: { environmentIds },
    });
    return this.list(transaction, actorUserId, projectId);
  }

  async delete(
    transaction: TenantTransaction,
    actorUserId: string,
    environmentId: string,
    options: { confirmSecrets?: boolean } = {},
  ): Promise<Environment> {
    const environment = await this.#get(transaction, actorUserId, environmentId);
    requirePermission(
      await this.#resolver.resolve(
        transaction,
        actorUserId,
        environment.projectId,
        environment.protected,
      ),
      "environment.delete",
    );
    const active = await transaction.query<{ environment_count: string; secret_count: string }>(
      `SELECT
         (SELECT count(*) FROM environments WHERE project_id = $1 AND deleted_at IS NULL)::text AS environment_count,
         (SELECT count(*) FROM secrets WHERE environment_id = $2 AND deleted_at IS NULL)::text AS secret_count`,
      [environment.projectId, environmentId],
    );
    if (Number(active.rows[0]?.environment_count ?? 0) <= 1) {
      throw new EnvironmentError("LAST_ENVIRONMENT", "A project must retain at least one active environment");
    }
    const secretCount = Number(active.rows[0]?.secret_count ?? 0);
    if (secretCount > 0 && options.confirmSecrets !== true) {
      throw new EnvironmentError(
        "SECRETS_REQUIRE_CONFIRMATION",
        "Confirm deletion because this environment contains active secrets",
      );
    }
    const deletedAt = this.#now();
    const purgeAfter = new Date(deletedAt.getTime() + this.#recoveryMs);
    await transaction.query(
      `UPDATE environments SET deleted_at = $1, purge_after = $2, updated_at = now()
       WHERE id = $3 AND deleted_at IS NULL`,
      [deletedAt, purgeAfter, environmentId],
    );
    await transaction.query(
      `UPDATE secrets SET deleted_at = $1, deleted_by_environment_at = $1, updated_at = now()
       WHERE environment_id = $2 AND deleted_at IS NULL`,
      [deletedAt, environmentId],
    );
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "environment.deleted",
      resource: { type: "environment", id: environmentId },
      projectId: environment.projectId,
      environmentId,
      after: { recoveryEndsAt: purgeAfter.toISOString(), deletedSecretCount: secretCount },
    });
    return { ...environment, deletedAt, purgeAfter };
  }

  async restore(
    transaction: TenantTransaction,
    actorUserId: string,
    environmentId: string,
  ): Promise<Environment> {
    const environment = await this.#get(transaction, actorUserId, environmentId, true);
    if (
      environment.deletedAt === null
      || environment.purgeAfter === null
      || environment.purgeAfter.getTime() <= this.#now().getTime()
    ) {
      throw new EnvironmentError("RECOVERY_EXPIRED", "Environment recovery window has expired");
    }
    const row = await transaction.query<{ deleted_by_project_at: Date | null }>(
      "SELECT deleted_by_project_at FROM environments WHERE id = $1",
      [environmentId],
    );
    if (row.rows[0]?.deleted_by_project_at !== null) {
      throw new EnvironmentError("NOT_FOUND", "Environment must be restored with its project");
    }
    await this.#requireActiveProject(transaction, environment.projectId);
    requirePermission(
      await this.#resolver.resolve(
        transaction,
        actorUserId,
        environment.projectId,
        environment.protected,
      ),
      "environment.delete",
    );
    await transaction.query(
      `UPDATE environments SET deleted_at = NULL, purge_after = NULL, updated_at = now()
       WHERE id = $1 AND deleted_at = $2 AND deleted_by_project_at IS NULL`,
      [environmentId, environment.deletedAt],
    );
    await transaction.query(
      `UPDATE secrets
       SET deleted_at = NULL, deleted_by_environment_at = NULL, updated_at = now()
       WHERE environment_id = $1
         AND deleted_by_environment_at = $2
         AND deleted_by_project_at IS NULL`,
      [environmentId, environment.deletedAt],
    );
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "environment.restored",
      resource: { type: "environment", id: environmentId },
      projectId: environment.projectId,
      environmentId,
    });
    return this.#get(transaction, actorUserId, environmentId);
  }

  async #get(
    transaction: TenantTransaction,
    actorUserId: string,
    environmentId: string,
    includeDeleted = false,
  ): Promise<Environment> {
    const result = await transaction.query<EnvironmentRow>(
      `SELECT id, org_id, project_id, name, slug, display_order, protected,
              deleted_at, purge_after, deleted_by_project_at
       FROM environments
       WHERE id = $1 ${includeDeleted ? "" : "AND deleted_at IS NULL"}`,
      [environmentId],
    );
    const row = result.rows[0];
    if (row === undefined) throw new EnvironmentError("NOT_FOUND", "Environment not found");
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, row.project_id), "environment.read");
    return fromRow(row);
  }

  async #requireActiveProject(transaction: TenantTransaction, projectId: string): Promise<void> {
    const project = await transaction.query("SELECT 1 FROM projects WHERE id = $1 AND deleted_at IS NULL", [projectId]);
    if (project.rowCount !== 1) throw new EnvironmentError("NOT_FOUND", "Project not found");
  }
}
