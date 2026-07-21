import type { AuditEventInput, AuditTransaction } from "@himitsu/audit";
import type { TenantTransaction } from "@himitsu/tenancy";

export const roles = ["owner", "admin", "member", "read_only"] as const;
export type Role = (typeof roles)[number];
export type ProjectOverrideRole = Exclude<Role, "owner">;

export const permissions = [
  "org.settings.read",
  "org.settings.update",
  "org.settings.delete",
  "org.members.read",
  "org.members.invite",
  "org.members.manage",
  "project.create",
  "project.read",
  "project.update",
  "project.archive",
  "project.delete",
  "environment.create",
  "environment.read",
  "environment.update",
  "environment.delete",
  "secret.read",
  "secret.write",
  "secret.delete",
  "api_key.read",
  "api_key.create",
  "api_key.revoke",
  "audit.read",
  "audit.export",
] as const;

export type Permission = (typeof permissions)[number];

const allPermissions: readonly Permission[] = permissions;

export const permissionMatrix: Readonly<Record<Role, readonly Permission[]>> = Object.freeze({
  owner: allPermissions,
  admin: allPermissions.filter((permission) => permission !== "org.settings.delete"),
  member: [
    "org.settings.read",
    "org.members.read",
    "project.create",
    "project.read",
    "project.update",
    "environment.create",
    "environment.read",
    "environment.update",
    "secret.read",
    "secret.write",
    "secret.delete",
  ],
  read_only: [
    "org.settings.read",
    "org.members.read",
    "project.read",
    "environment.read",
    "secret.read",
  ],
});

const roleRank: Readonly<Record<Role, number>> = {
  read_only: 0,
  member: 1,
  admin: 2,
  owner: 3,
};

const projectScopedPermissions = new Set<Permission>([
  "project.read",
  "project.update",
  "project.archive",
  "project.delete",
  "environment.create",
  "environment.read",
  "environment.update",
  "environment.delete",
  "secret.read",
  "secret.write",
  "secret.delete",
  "api_key.read",
  "api_key.create",
  "api_key.revoke",
]);

const protectedWritePermissions = new Set<Permission>([
  "environment.update",
  "environment.delete",
  "secret.write",
  "secret.delete",
]);

export interface AuthorizationContext {
  readonly orgRole: Role;
  readonly projectRole?: ProjectOverrideRole | null;
  readonly protectedEnvironment?: boolean;
}

export interface AuthorizationDecision {
  readonly allowed: boolean;
  readonly permission: Permission;
  readonly effectiveRole: Role;
  readonly reason: "allowed" | "role" | "protected_environment";
}

export function effectiveRole(orgRole: Role, projectRole?: ProjectOverrideRole | null): Role {
  if (projectRole === null || projectRole === undefined) return orgRole;
  return roleRank[projectRole] < roleRank[orgRole] ? projectRole : orgRole;
}

export function authorize(
  context: AuthorizationContext,
  permission: Permission,
): AuthorizationDecision {
  const role = projectScopedPermissions.has(permission)
    ? effectiveRole(context.orgRole, context.projectRole)
    : context.orgRole;
  if (!permissionMatrix[role].includes(permission)) {
    return { allowed: false, permission, effectiveRole: role, reason: "role" };
  }
  if (
    context.protectedEnvironment === true &&
    protectedWritePermissions.has(permission) &&
    role !== "owner" &&
    role !== "admin"
  ) {
    return { allowed: false, permission, effectiveRole: role, reason: "protected_environment" };
  }
  return { allowed: true, permission, effectiveRole: role, reason: "allowed" };
}

export class AuthorizationError extends Error {
  readonly code = "FORBIDDEN" as const;
  readonly decision: AuthorizationDecision;

  constructor(decision: AuthorizationDecision) {
    super(`Permission denied: ${decision.permission}`);
    this.name = "AuthorizationError";
    this.decision = decision;
  }
}

export function requirePermission(context: AuthorizationContext, permission: Permission): void {
  const decision = authorize(context, permission);
  if (!decision.allowed) throw new AuthorizationError(decision);
}

export function authorizationSnapshot(
  context: AuthorizationContext,
): Readonly<Record<Permission, boolean>> {
  return Object.freeze(
    Object.fromEntries(
      permissions.map((permission) => [permission, authorize(context, permission).allowed]),
    ) as Record<Permission, boolean>,
  );
}

export class AuthorizationContextResolver {
  async resolve(
    transaction: TenantTransaction,
    userId: string,
    projectId?: string,
    protectedEnvironment = false,
  ): Promise<AuthorizationContext> {
    const membership = await transaction.query<{ role: Role }>(
      "SELECT role FROM memberships WHERE user_id = $1 AND status = 'active'",
      [userId],
    );
    const orgRole = membership.rows[0]?.role;
    if (orgRole === undefined) {
      throw new AuthorizationError({
        allowed: false,
        permission: "org.settings.read",
        effectiveRole: "read_only",
        reason: "role",
      });
    }
    let projectRole: ProjectOverrideRole | null = null;
    if (projectId !== undefined) {
      const override = await transaction.query<{ role: ProjectOverrideRole }>(
        "SELECT role FROM project_role_overrides WHERE project_id = $1 AND user_id = $2",
        [projectId, userId],
      );
      projectRole = override.rows[0]?.role ?? null;
    }
    return { orgRole, projectRole, protectedEnvironment };
  }
}

interface AuditRecorder {
  recordInTransaction(transaction: AuditTransaction, event: AuditEventInput): Promise<void>;
}

export class ProjectRoleOverrideService {
  readonly #resolver: AuthorizationContextResolver;
  readonly #audit: AuditRecorder;

  constructor(resolver: AuthorizationContextResolver, audit: AuditRecorder) {
    this.#resolver = resolver;
    this.#audit = audit;
  }

  async setOverride(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    targetUserId: string,
    role: ProjectOverrideRole,
  ): Promise<void> {
    requirePermission(await this.#resolver.resolve(transaction, actorUserId), "org.members.manage");
    const target = await transaction.query<{ role: Role }>(
      "SELECT role FROM memberships WHERE user_id = $1 AND status = 'active'",
      [targetUserId],
    );
    if (target.rows[0] === undefined) throw new AuthorizationError({
      allowed: false,
      permission: "org.members.manage",
      effectiveRole: "read_only",
      reason: "role",
    });
    const previous = await transaction.query<{ role: ProjectOverrideRole }>(
      "SELECT role FROM project_role_overrides WHERE project_id = $1 AND user_id = $2",
      [projectId, targetUserId],
    );
    await transaction.query(
      `INSERT INTO project_role_overrides
        (org_id, project_id, user_id, role, created_by_user_id)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (org_id, project_id, user_id) DO UPDATE
         SET role = EXCLUDED.role, updated_at = now(), created_by_user_id = EXCLUDED.created_by_user_id`,
      [transaction.orgId, projectId, targetUserId, role, actorUserId],
    );
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "membership.project_role_changed",
      resource: { type: "project_membership", id: `${projectId}:${targetUserId}` },
      projectId,
      before: { role: previous.rows[0]?.role ?? null },
      after: { role, targetUserId },
    });
  }

  async removeOverride(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    targetUserId: string,
  ): Promise<void> {
    requirePermission(await this.#resolver.resolve(transaction, actorUserId), "org.members.manage");
    const removed = await transaction.query<{ role: ProjectOverrideRole }>(
      "DELETE FROM project_role_overrides WHERE project_id = $1 AND user_id = $2 RETURNING role",
      [projectId, targetUserId],
    );
    if (removed.rows[0] !== undefined) {
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: { type: "user", id: actorUserId },
        action: "membership.project_role_changed",
        resource: { type: "project_membership", id: `${projectId}:${targetUserId}` },
        projectId,
        before: { role: removed.rows[0].role },
        after: { role: null, targetUserId },
      });
    }
  }
}
