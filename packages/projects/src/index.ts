import type { AuditEventInput, AuditTransaction, TransactionalAuditLog } from "@himitsu/audit";
import {
  AuthorizationContextResolver,
  requirePermission,
} from "@himitsu/authz";
import type { TenantTransaction } from "@himitsu/tenancy";

const DEFAULT_RECOVERY_DAYS = 30;

export class ProjectError extends Error {
  readonly code:
    | "INVALID_INPUT"
    | "SLUG_EXISTS"
    | "NOT_FOUND"
    | "TAG_NOT_FOUND"
    | "RECOVERY_EXPIRED";

  constructor(code: ProjectError["code"], message: string) {
    super(message);
    this.name = "ProjectError";
    this.code = code;
  }
}

export interface ProjectSettings {
  readonly defaultEnvironments: readonly string[];
}

export interface ProjectTag {
  readonly id: string;
  readonly name: string;
  readonly color: string;
}

export interface Project {
  readonly id: string;
  readonly orgId: string;
  readonly name: string;
  readonly slug: string;
  readonly description: string | null;
  readonly settings: ProjectSettings;
  readonly tagIds: readonly string[];
  readonly tags: readonly ProjectTag[];
  /** Active environments in display order; always reflects the live environment table, never the defaults setting. */
  readonly environments: readonly ProjectEnvironmentSummary[];
  readonly archivedAt: Date | null;
  readonly deletedAt: Date | null;
  readonly purgeAfter: Date | null;
}

export interface ProjectEnvironmentSummary {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly protected: boolean;
}

interface ProjectRow {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  description: string | null;
  settings: { defaultEnvironments?: unknown };
  archived_at: Date | null;
  deleted_at: Date | null;
  purge_after: Date | null;
  tag_ids: string[] | null;
  tags: ProjectTag[] | null;
  environments: ProjectEnvironmentSummary[] | null;
}

interface AuditRecorder {
  recordInTransaction(transaction: AuditTransaction, event: AuditEventInput): Promise<void>;
}

export function normalizeProjectSlug(slug: string): string {
  const normalized = slug.trim().toLowerCase();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(normalized) || normalized.length > 80) {
    throw new ProjectError("INVALID_INPUT", "Project slug must use lowercase words separated by hyphens");
  }
  return normalized;
}

function projectName(name: string): string {
  const normalized = name.trim();
  if (normalized.length < 1 || normalized.length > 120) {
    throw new ProjectError("INVALID_INPUT", "Project name must be between 1 and 120 characters");
  }
  return normalized;
}

function projectDescription(description: string | null | undefined): string | null {
  if (description === null || description === undefined || description.trim() === "") return null;
  const normalized = description.trim();
  if (normalized.length > 4000) throw new ProjectError("INVALID_INPUT", "Project description is too long");
  return normalized;
}

export function validateDefaultEnvironments(values: readonly string[] | undefined): readonly string[] {
  const environments = values ?? ["development", "staging", "production"];
  if (environments.length < 1 || environments.length > 20) {
    throw new ProjectError("INVALID_INPUT", "Projects require between 1 and 20 default environments");
  }
  const normalized = environments.map(normalizeProjectSlug);
  if (new Set(normalized).size !== normalized.length) {
    throw new ProjectError("INVALID_INPUT", "Default environment slugs must be unique");
  }
  return normalized;
}

function fromRow(row: ProjectRow): Project {
  const defaultEnvironments = validateDefaultEnvironments(
    Array.isArray(row.settings.defaultEnvironments)
      ? row.settings.defaultEnvironments.filter((value): value is string => typeof value === "string")
      : undefined,
  );
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    slug: row.slug,
    description: row.description,
    settings: { defaultEnvironments },
    tagIds: row.tag_ids ?? [],
    tags: row.tags ?? [],
    environments: row.environments ?? [],
    archivedAt: row.archived_at,
    deletedAt: row.deleted_at,
    purgeAfter: row.purge_after,
  };
}

const projectSelect = `
  SELECT p.id, p.org_id, p.name, p.slug, p.description, p.settings,
         p.archived_at, p.deleted_at, p.purge_after,
         COALESCE(array_agg(pt.tag_id ORDER BY lower(t.name), pt.tag_id) FILTER (WHERE pt.tag_id IS NOT NULL), '{}') AS tag_ids,
         COALESCE(jsonb_agg(jsonb_build_object('id', t.id, 'name', t.name, 'color', t.color)
           ORDER BY lower(t.name), t.id) FILTER (WHERE t.id IS NOT NULL), '[]'::jsonb) AS tags,
         (SELECT COALESCE(jsonb_agg(jsonb_build_object('id', e.id, 'name', e.name, 'slug', e.slug, 'protected', e.protected)
                   ORDER BY e.display_order, e.id), '[]'::jsonb)
          FROM environments e WHERE e.project_id = p.id AND e.deleted_at IS NULL) AS environments
  FROM projects p
  LEFT JOIN project_tags pt ON pt.project_id = p.id AND pt.org_id = p.org_id
  LEFT JOIN tags t ON t.id = pt.tag_id AND t.org_id = pt.org_id`;

export class ProjectService {
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
      throw new ProjectError("INVALID_INPUT", "Recovery days must be between 1 and 365");
    }
    this.#recoveryMs = recoveryDays * 24 * 60 * 60 * 1000;
  }

  async create(
    transaction: TenantTransaction,
    actorUserId: string,
    input: {
      name: string;
      slug: string;
      description?: string | null;
      defaultEnvironments?: readonly string[];
      tagIds?: readonly string[];
    },
  ): Promise<Project> {
    requirePermission(await this.#resolver.resolve(transaction, actorUserId), "project.create");
    const settings: ProjectSettings = {
      defaultEnvironments: validateDefaultEnvironments(input.defaultEnvironments),
    };
    try {
      const inserted = await transaction.query<{ id: string }>(
        `INSERT INTO projects (org_id, name, slug, description, settings, created_by_user_id)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [
          transaction.orgId,
          projectName(input.name),
          normalizeProjectSlug(input.slug),
          projectDescription(input.description),
          settings,
          actorUserId,
        ],
      );
      const projectId = inserted.rows[0]?.id;
      if (projectId === undefined) throw new Error("Project insertion returned no row");
      await this.#replaceTags(transaction, projectId, input.tagIds ?? []);
      const project = await this.#getById(transaction, actorUserId, projectId, true);
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: { type: "user", id: actorUserId },
        action: "project.created",
        resource: { type: "project", id: projectId },
        projectId,
        after: {
          name: project.name,
          slug: project.slug,
          defaultEnvironments: project.settings.defaultEnvironments,
          tagIds: project.tagIds,
        },
      });
      return project;
    } catch (error) {
      if ((error as { code?: string }).code === "23505") {
        throw new ProjectError("SLUG_EXISTS", "Project slug is already in use in this organization");
      }
      throw error;
    }
  }

  async getBySlug(
    transaction: TenantTransaction,
    actorUserId: string,
    slug: string,
    includeDeleted = false,
  ): Promise<Project> {
    const result = await transaction.query<ProjectRow>(
      `${projectSelect}
       WHERE p.slug = $1 ${includeDeleted ? "" : "AND p.deleted_at IS NULL"}
       GROUP BY p.id`,
      [normalizeProjectSlug(slug)],
    );
    const row = result.rows[0];
    if (row === undefined) throw new ProjectError("NOT_FOUND", "Project not found");
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, row.id), "project.read");
    return fromRow(row);
  }

  async getById(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    includeDeleted = false,
  ): Promise<Project> {
    return this.#getById(transaction, actorUserId, projectId, includeDeleted);
  }

  async list(transaction: TenantTransaction, actorUserId: string): Promise<readonly Project[]> {
    requirePermission(await this.#resolver.resolve(transaction, actorUserId), "project.read");
    const result = await transaction.query<ProjectRow>(
      `${projectSelect} WHERE p.deleted_at IS NULL GROUP BY p.id ORDER BY lower(p.name), p.id`,
    );
    return result.rows.map(fromRow);
  }

  async update(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    input: {
      name?: string;
      slug?: string;
      description?: string | null;
      defaultEnvironments?: readonly string[];
      tagIds?: readonly string[];
    },
  ): Promise<Project> {
    const before = await this.#getById(transaction, actorUserId, projectId);
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, projectId), "project.update");
    const name = input.name === undefined ? before.name : projectName(input.name);
    const slug = input.slug === undefined ? before.slug : normalizeProjectSlug(input.slug);
    const description = input.description === undefined
      ? before.description
      : projectDescription(input.description);
    const settings: ProjectSettings = {
      defaultEnvironments: input.defaultEnvironments === undefined
        ? before.settings.defaultEnvironments
        : validateDefaultEnvironments(input.defaultEnvironments),
    };
    try {
      await transaction.query(
        `UPDATE projects SET name = $1, slug = $2, description = $3, settings = $4, updated_at = now()
         WHERE id = $5 AND deleted_at IS NULL`,
        [name, slug, description, settings, projectId],
      );
      if (input.tagIds !== undefined) await this.#replaceTags(transaction, projectId, input.tagIds);
      const after = await this.#getById(transaction, actorUserId, projectId);
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: { type: "user", id: actorUserId },
        action: "project.updated",
        resource: { type: "project", id: projectId },
        projectId,
        before: { name: before.name, slug: before.slug },
        after: { name: after.name, slug: after.slug },
      });
      return after;
    } catch (error) {
      if ((error as { code?: string }).code === "23505") {
        throw new ProjectError("SLUG_EXISTS", "Project slug is already in use in this organization");
      }
      throw error;
    }
  }

  async setArchived(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    archived: boolean,
  ): Promise<Project> {
    await this.#getById(transaction, actorUserId, projectId);
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, projectId), "project.archive");
    await transaction.query(
      "UPDATE projects SET archived_at = CASE WHEN $1 THEN now() ELSE NULL END, updated_at = now() WHERE id = $2 AND deleted_at IS NULL",
      [archived, projectId],
    );
    const project = await this.#getById(transaction, actorUserId, projectId);
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "project.archived",
      resource: { type: "project", id: projectId },
      projectId,
      after: { archived },
    });
    return project;
  }

  async delete(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
  ): Promise<Project> {
    await this.#getById(transaction, actorUserId, projectId);
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, projectId), "project.delete");
    const deletedAt = this.#now();
    const purgeAfter = new Date(deletedAt.getTime() + this.#recoveryMs);
    await transaction.query(
      `UPDATE projects SET deleted_at = $1, purge_after = $2, updated_at = now()
       WHERE id = $3 AND deleted_at IS NULL`,
      [deletedAt, purgeAfter, projectId],
    );
    await transaction.query(
      `UPDATE environments SET deleted_at = $1, deleted_by_project_at = $1, updated_at = now()
       WHERE project_id = $2 AND deleted_at IS NULL`,
      [deletedAt, projectId],
    );
    await transaction.query(
      `UPDATE secrets SET deleted_at = $1, deleted_by_project_at = $1, updated_at = now()
       WHERE project_id = $2 AND deleted_at IS NULL`,
      [deletedAt, projectId],
    );
    const project = await this.#getById(transaction, actorUserId, projectId, true);
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "project.deleted",
      resource: { type: "project", id: projectId },
      projectId,
      after: { recoveryEndsAt: purgeAfter.toISOString() },
    });
    return project;
  }

  async restore(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
  ): Promise<Project> {
    const project = await this.#getById(transaction, actorUserId, projectId, true);
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, projectId), "project.delete");
    if (project.deletedAt === null || project.purgeAfter === null) {
      throw new ProjectError("NOT_FOUND", "Deleted project not found");
    }
    if (project.purgeAfter.getTime() <= this.#now().getTime()) {
      throw new ProjectError("RECOVERY_EXPIRED", "Project recovery window has expired");
    }
    await transaction.query(
      "UPDATE projects SET deleted_at = NULL, purge_after = NULL, updated_at = now() WHERE id = $1",
      [projectId],
    );
    await transaction.query(
      `UPDATE environments SET deleted_at = NULL, deleted_by_project_at = NULL, updated_at = now()
       WHERE project_id = $1 AND deleted_by_project_at = $2`,
      [projectId, project.deletedAt],
    );
    await transaction.query(
      `UPDATE secrets SET deleted_at = NULL, deleted_by_project_at = NULL, updated_at = now()
       WHERE project_id = $1 AND deleted_by_project_at = $2`,
      [projectId, project.deletedAt],
    );
    const restored = await this.#getById(transaction, actorUserId, projectId);
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "project.restored",
      resource: { type: "project", id: projectId },
      projectId,
    });
    return restored;
  }

  async #getById(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    includeDeleted = false,
  ): Promise<Project> {
    const result = await transaction.query<ProjectRow>(
      `${projectSelect}
       WHERE p.id = $1 ${includeDeleted ? "" : "AND p.deleted_at IS NULL"}
       GROUP BY p.id`,
      [projectId],
    );
    const row = result.rows[0];
    if (row === undefined) throw new ProjectError("NOT_FOUND", "Project not found");
    requirePermission(await this.#resolver.resolve(transaction, actorUserId, row.id), "project.read");
    return fromRow(row);
  }

  async #replaceTags(
    transaction: TenantTransaction,
    projectId: string,
    tagIds: readonly string[],
  ): Promise<void> {
    const uniqueTagIds = [...new Set(tagIds)];
    if (uniqueTagIds.length > 50) throw new ProjectError("INVALID_INPUT", "A project can have at most 50 tags");
    if (uniqueTagIds.length !== 0) {
      const found = await transaction.query<{ id: string }>(
        "SELECT id FROM tags WHERE id = ANY($1::uuid[])",
        [uniqueTagIds],
      );
      if (found.rowCount !== uniqueTagIds.length) {
        throw new ProjectError("TAG_NOT_FOUND", "One or more project tags do not exist in this organization");
      }
    }
    await transaction.query("DELETE FROM project_tags WHERE project_id = $1", [projectId]);
    if (uniqueTagIds.length !== 0) {
      await transaction.query(
        `INSERT INTO project_tags (org_id, project_id, tag_id)
         SELECT $1, $2, unnest($3::uuid[])`,
        [transaction.orgId, projectId, uniqueTagIds],
      );
    }
  }
}
