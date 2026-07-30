import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { AuditEventInput, AuditTransaction, TransactionalAuditLog } from "@himitsu/audit";
import type { Pool, PoolClient, QueryResult, QueryResultRow } from "pg";

/** Lifetime of an organization invitation. Exported so delivery templates can state
 *  the expiry without hardcoding a value that could drift. */
export const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export type OrganizationRole = "owner" | "admin" | "member" | "read_only";
export type InvitationalRole = Exclude<OrganizationRole, "owner">;

export class TenancyError extends Error {
  readonly code:
    | "INVALID_INPUT"
    | "SLUG_EXISTS"
    | "INVITATION_EXISTS"
    | "INVITATION_INVALID"
    | "INVITATION_EMAIL_MISMATCH"
    | "ALREADY_MEMBER"
    | "MEMBERSHIP_REQUIRED"
    | "INVITE_FORBIDDEN";

  constructor(code: TenancyError["code"], message: string) {
    super(message);
    this.name = "TenancyError";
    this.code = code;
  }
}

export interface InvitationDelivery {
  sendOrganizationInvitation(input: {
    readonly email: string;
    readonly organizationName: string;
    readonly inviterUserId: string;
    readonly token: string;
  }): Promise<void>;
}

export interface OrganizationOption {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly role: OrganizationRole;
  readonly active: boolean;
}

export interface TenantTransaction extends AuditTransaction {
  readonly orgId: string;
  readonly userId: string;
  query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<QueryResult<Row>>;
}

function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 320 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)) {
    throw new TenancyError("INVALID_INPUT", "A valid invitation email is required");
  }
  return normalized;
}

export function normalizeOrganizationSlug(slug: string): string {
  const normalized = slug.trim().toLowerCase();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(normalized) || normalized.length > 80) {
    throw new TenancyError("INVALID_INPUT", "Organization slug must use lowercase words separated by hyphens");
  }
  return normalized;
}

function validateOrganizationName(name: string): string {
  const normalized = name.trim();
  if (normalized.length < 1 || normalized.length > 120) {
    throw new TenancyError("INVALID_INPUT", "Organization name must be between 1 and 120 characters");
  }
  return normalized;
}

function tokenDigest(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

function invitationToken(): string {
  return randomBytes(32).toString("base64url");
}

interface AuditRecorder {
  recordInTransaction(transaction: AuditTransaction, event: AuditEventInput): Promise<void>;
}

class BoundTenantTransaction implements TenantTransaction {
  readonly orgId: string;
  readonly userId: string;
  readonly #client: PoolClient;

  constructor(client: PoolClient, orgId: string, userId: string) {
    this.#client = client;
    this.orgId = orgId;
    this.userId = userId;
  }

  query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values: readonly unknown[] = [],
  ): Promise<QueryResult<Row>> {
    return this.#client.query<Row>(text, [...values]);
  }
}

export class TenantDatabase {
  readonly #pool: Pool;

  constructor(pool: Pool) {
    this.#pool = pool;
  }

  async withOrg<T>(
    orgId: string,
    userId: string,
    work: (transaction: TenantTransaction) => Promise<T>,
  ): Promise<T> {
    return this.#withOrgContext(orgId, userId, true, work);
  }

  async #withOrgContext<T>(
    orgId: string,
    userId: string,
    requireMembership: boolean,
    work: (transaction: TenantTransaction) => Promise<T>,
  ): Promise<T> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.current_org_id', $1, true)", [orgId]);
      await client.query("SELECT set_config('app.current_user_id', $1, true)", [userId]);
      const transaction = new BoundTenantTransaction(client, orgId, userId);
      if (requireMembership) {
        const membership = await transaction.query(
          "SELECT 1 FROM memberships WHERE org_id = $1 AND user_id = $2 AND status = 'active'",
          [orgId, userId],
        );
        if (membership.rowCount !== 1) {
          throw new TenancyError("MEMBERSHIP_REQUIRED", "Active organization membership is required");
        }
      }
      const result = await work(transaction);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async createOrganization(
    userId: string,
    name: string,
    slug: string,
    audit: AuditRecorder,
  ): Promise<{ id: string; name: string; slug: string }> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const organizationId = randomUUID();
      await client.query("SELECT set_config('app.current_org_id', $1, true)", [organizationId]);
      await client.query("SELECT set_config('app.current_user_id', $1, true)", [userId]);
      const inserted = await client.query<{ id: string; name: string; slug: string }>(
        "INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3) RETURNING id, name, slug",
        [organizationId, name, slug],
      );
      const organization = inserted.rows[0];
      if (organization === undefined) throw new Error("Organization insertion returned no row");
      const transaction = new BoundTenantTransaction(client, organization.id, userId);
      await transaction.query(
        "INSERT INTO memberships (org_id, user_id, role, status) VALUES ($1, $2, 'owner', 'active')",
        [organization.id, userId],
      );
      await audit.recordInTransaction(transaction, {
        orgId: organization.id,
        actor: { type: "user", id: userId },
        action: "organization.created",
        resource: { type: "organization", id: organization.id },
        after: { name: organization.name, slug: organization.slug },
      });
      await client.query("COMMIT");
      return organization;
    } catch (error) {
      await client.query("ROLLBACK");
      if ((error as { code?: string }).code === "23505") {
        throw new TenancyError("SLUG_EXISTS", "Organization slug is already in use");
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async listOrganizationOptions(userId: string, activeOrgId: string | null): Promise<OrganizationOption[]> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.current_user_id', $1, true)", [userId]);
      await client.query("SELECT set_config('app.membership_discovery', 'on', true)");
      const result = await client.query<{
        id: string;
        name: string;
        slug: string;
        role: OrganizationRole;
      }>(
        `SELECT o.id, o.name, o.slug, m.role
         FROM memberships m JOIN organizations o ON o.id = m.org_id
         WHERE m.user_id = $1 AND m.status = 'active' AND o.deleted_at IS NULL
         ORDER BY lower(o.name), o.id`,
        [userId],
      );
      await client.query("COMMIT");
      return result.rows.map((row) => ({ ...row, active: row.id === activeOrgId }));
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async switchActiveOrganization(sessionId: string, userId: string, orgId: string): Promise<void> {
    await this.withOrg(orgId, userId, async (transaction) => {
      const membership = await transaction.query(
        "SELECT 1 FROM memberships WHERE org_id = $1 AND user_id = $2 AND status = 'active'",
        [orgId, userId],
      );
      if (membership.rowCount !== 1) {
        throw new TenancyError("MEMBERSHIP_REQUIRED", "Active organization membership is required");
      }
      const updated = await transaction.query(
        `UPDATE sessions SET active_org_id = $1
         WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL AND expires_at > now()`,
        [orgId, sessionId, userId],
      );
      if (updated.rowCount !== 1) {
        throw new TenancyError("MEMBERSHIP_REQUIRED", "An active session is required to switch organizations");
      }
    });
  }

  async withActiveOrganization<T>(
    sessionId: string,
    userId: string,
    work: (transaction: TenantTransaction) => Promise<T>,
  ): Promise<T> {
    const session = await this.#pool.query<{ active_org_id: string | null }>(
      `SELECT active_org_id FROM sessions
       WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()`,
      [sessionId, userId],
    );
    const orgId = session.rows[0]?.active_org_id;
    if (orgId === null || orgId === undefined) {
      throw new TenancyError("MEMBERSHIP_REQUIRED", "Select an active organization first");
    }
    return this.withOrg(orgId, userId, work);
  }

  async createInvitation(input: {
    orgId: string;
    inviterUserId: string;
    email: string;
    role: InvitationalRole;
    token: string;
    expiresAt: Date;
    audit: AuditRecorder;
  }): Promise<{ organizationName: string }> {
    return this.withOrg(input.orgId, input.inviterUserId, async (transaction) => {
      const inviter = await transaction.query<{ role: OrganizationRole }>(
        "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2 AND status = 'active'",
        [input.orgId, input.inviterUserId],
      );
      if (!(["owner", "admin"] as OrganizationRole[]).includes(inviter.rows[0]?.role ?? "member")) {
        throw new TenancyError("INVITE_FORBIDDEN", "Owner or admin membership is required to invite members");
      }
      const organization = await transaction.query<{ name: string }>(
        "SELECT name FROM organizations WHERE id = $1 AND deleted_at IS NULL",
        [input.orgId],
      );
      const existingMember = await transaction.query(
        `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
         WHERE m.org_id = $1 AND u.email_normalized = $2 AND m.status = 'active'`,
        [input.orgId, input.email],
      );
      if (existingMember.rowCount !== 0) {
        throw new TenancyError("ALREADY_MEMBER", "This user is already an organization member");
      }
      try {
        await transaction.query(
          `UPDATE organization_invitations SET revoked_at = now()
           WHERE org_id = $1 AND email_normalized = $2
             AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= now()`,
          [input.orgId, input.email],
        );
        const invitation = await transaction.query<{ id: string }>(
          `INSERT INTO organization_invitations
            (org_id, email, role, token_hash, invited_by_user_id, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
          [input.orgId, input.email, input.role, tokenDigest(input.token), input.inviterUserId, input.expiresAt],
        );
        const invitationId = invitation.rows[0]?.id;
        if (invitationId === undefined) throw new Error("Invitation insertion returned no row");
        await input.audit.recordInTransaction(transaction, {
          orgId: input.orgId,
          actor: { type: "user", id: input.inviterUserId },
          action: "membership.invited",
          resource: { type: "organization_invitation", id: invitationId },
          after: { email: input.email, role: input.role },
        });
      } catch (error) {
        if ((error as { code?: string }).code === "23505") {
          throw new TenancyError("INVITATION_EXISTS", "A pending invitation already exists for this email");
        }
        throw error;
      }
      return { organizationName: organization.rows[0]?.name ?? "Organization" };
    });
  }

  async acceptInvitation(input: {
    token: string;
    userId: string;
    userEmail: string;
    audit: AuditRecorder;
  }): Promise<string> {
    const resolved = await this.#pool.query<{ org_id: string | null }>(
      "SELECT resolve_invitation_org($1) AS org_id",
      [tokenDigest(input.token)],
    );
    const orgId = resolved.rows[0]?.org_id;
    if (orgId === null || orgId === undefined) {
      throw new TenancyError("INVITATION_INVALID", "Invitation is invalid or expired");
    }
    return this.#withOrgContext(orgId, input.userId, false, async (transaction) => {
      const invitation = await transaction.query<{
        id: string;
        email_normalized: string;
        role: InvitationalRole;
        invited_by_user_id: string;
      }>(
        `SELECT id, email_normalized, role, invited_by_user_id
         FROM organization_invitations
         WHERE token_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL
           AND expires_at > now() FOR UPDATE`,
        [tokenDigest(input.token)],
      );
      const record = invitation.rows[0];
      if (record === undefined) throw new TenancyError("INVITATION_INVALID", "Invitation is invalid or expired");
      if (record.email_normalized !== normalizeEmail(input.userEmail)) {
        throw new TenancyError("INVITATION_EMAIL_MISMATCH", "Invitation belongs to another email address");
      }
      await transaction.query(
        `INSERT INTO memberships (org_id, user_id, role, status, invited_by_user_id)
         VALUES ($1, $2, $3, 'active', $4)`,
        [orgId, input.userId, record.role, record.invited_by_user_id],
      );
      await transaction.query(
        "UPDATE organization_invitations SET accepted_at = now(), accepted_by_user_id = $1 WHERE id = $2",
        [input.userId, record.id],
      );
      await input.audit.recordInTransaction(transaction, {
        orgId,
        actor: { type: "user", id: input.userId },
        action: "membership.accepted",
        resource: { type: "membership", id: input.userId },
        after: { role: record.role },
      });
      return orgId;
    });
  }
}

export class TenancyService {
  readonly #database: TenantDatabase;
  readonly #delivery: InvitationDelivery;
  readonly #audit: AuditRecorder;
  readonly #now: () => Date;

  constructor(
    database: TenantDatabase,
    delivery: InvitationDelivery,
    audit: TransactionalAuditLog,
    options: { now?: () => Date } = {},
  ) {
    this.#database = database;
    this.#delivery = delivery;
    this.#audit = audit;
    this.#now = options.now ?? (() => new Date());
  }

  async createOrganization(userId: string, name: string, slug: string) {
    return this.#database.createOrganization(
      userId,
      validateOrganizationName(name),
      normalizeOrganizationSlug(slug),
      this.#audit,
    );
  }

  async inviteMember(input: {
    orgId: string;
    inviterUserId: string;
    email: string;
    role: InvitationalRole;
  }): Promise<void> {
    const email = normalizeEmail(input.email);
    const token = invitationToken();
    const result = await this.#database.createInvitation({
      ...input,
      email,
      token,
      expiresAt: new Date(this.#now().getTime() + INVITATION_TTL_MS),
      audit: this.#audit,
    });
    await this.#delivery.sendOrganizationInvitation({
      email,
      organizationName: result.organizationName,
      inviterUserId: input.inviterUserId,
      token,
    });
  }

  async acceptInvitation(token: string, userId: string, userEmail: string): Promise<string> {
    return this.#database.acceptInvitation({ token, userId, userEmail, audit: this.#audit });
  }

  listOrganizations(userId: string, activeOrgId: string | null): Promise<OrganizationOption[]> {
    return this.#database.listOrganizationOptions(userId, activeOrgId);
  }

  switchOrganization(sessionId: string, userId: string, orgId: string): Promise<void> {
    return this.#database.switchActiveOrganization(sessionId, userId, orgId);
  }
}
