import type { Pool, QueryResult, QueryResultRow } from "pg";

export type AuditAction =
  | "organization.created"
  | "organization.audit_retention_updated"
  | "auth.signup"
  | "auth.email_verified"
  | "auth.login_succeeded"
  | "auth.login_failed"
  | "auth.logout"
  | "auth.password_reset_requested"
  | "auth.password_reset_completed"
  | "api_key.used"
  | "api_key.created"
  | "api_key.revoked"
  | "project.created"
  | "project.updated"
  | "project.archived"
  | "project.restored"
  | "project.deleted"
  | "environment.created"
  | "environment.updated"
  | "environment.reordered"
  | "environment.deleted"
  | "environment.restored"
  | "consistency.acknowledged"
  | "consistency.ignored"
  | "consistency.cleared"
  | "secret.created"
  | "secret.read"
  | "secret.updated"
  | "secret.deleted"
  | "secret.exported"
  | "secret.imported"
  | "secret.promoted"
  | "membership.invited"
  | "membership.accepted"
  | "membership.removed"
  | "membership.role_changed"
  | "membership.project_role_changed";

export type AuditActor =
  | { readonly type: "user"; readonly id: string }
  | { readonly type: "api_key"; readonly id: string }
  | { readonly type: "system" };

export type SafeMetadataValue =
  | null
  | boolean
  | number
  | string
  | readonly SafeMetadataValue[]
  | { readonly [key: string]: SafeMetadataValue };

export interface AuditEventInput {
  readonly orgId: string;
  readonly actor: AuditActor;
  readonly action: AuditAction;
  readonly resource: { readonly type: string; readonly id?: string };
  readonly projectId?: string;
  readonly environmentId?: string;
  readonly ip?: string;
  readonly userAgent?: string;
  readonly before?: Readonly<Record<string, SafeMetadataValue>>;
  readonly after?: Readonly<Record<string, SafeMetadataValue>>;
  readonly details?: Readonly<Record<string, SafeMetadataValue>>;
}

export class AuditError extends Error {
  readonly code: "UNSAFE_METADATA" | "INVALID_EVENT";

  constructor(code: AuditError["code"], message: string) {
    super(message);
    this.name = "AuditError";
    this.code = code;
  }
}

const forbiddenKey = /(?:^|_)(?:secret|value|password|passphrase|token|credential|authorization|cookie|ciphertext|nonce|auth_tag)(?:$|_)/i;

function validateMetadata(value: SafeMetadataValue, path: string, depth: number): void {
  if (depth > 8) throw new AuditError("UNSAFE_METADATA", `Audit metadata is too deep at ${path}`);
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new AuditError("UNSAFE_METADATA", `Non-finite number at ${path}`);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 100) throw new AuditError("UNSAFE_METADATA", `Audit array is too large at ${path}`);
    value.forEach((item, index) => validateMetadata(item, `${path}[${index}]`, depth + 1));
    return;
  }
  const entries = Object.entries(value);
  if (entries.length > 100) throw new AuditError("UNSAFE_METADATA", `Audit object is too large at ${path}`);
  for (const [key, child] of entries) {
    if (forbiddenKey.test(key)) {
      throw new AuditError("UNSAFE_METADATA", `Forbidden audit metadata field at ${path}.${key}`);
    }
    validateMetadata(child, `${path}.${key}`, depth + 1);
  }
}

function metadataFor(event: AuditEventInput): Record<string, SafeMetadataValue> {
  const metadata: Record<string, SafeMetadataValue> = {};
  for (const [key, value] of [
    ["before", event.before],
    ["after", event.after],
    ["details", event.details],
  ] as const) {
    if (value !== undefined) {
      validateMetadata(value, key, 0);
      metadata[key] = value;
    }
  }
  const encoded = JSON.stringify(metadata);
  if (Buffer.byteLength(encoded, "utf8") > 64 * 1024) {
    throw new AuditError("UNSAFE_METADATA", "Audit metadata exceeds 64 KiB");
  }
  return metadata;
}

function validateEvent(event: AuditEventInput): void {
  if (!event.orgId || !event.action || !event.resource.type) {
    throw new AuditError("INVALID_EVENT", "Audit event identity fields are required");
  }
  if (event.actor.type !== "system" && !event.actor.id) {
    throw new AuditError("INVALID_EVENT", "Audit actor id is required");
  }
  if (event.action.startsWith("secret.") && event.resource.id === undefined) {
    throw new AuditError("INVALID_EVENT", "Secret audit events require a resource id");
  }
}

export interface AuditTransaction {
  query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<QueryResult<Row>>;
}

export interface AuditEventView {
  readonly id: string;
  readonly actor: { readonly type: AuditActor["type"]; readonly id: string | null; readonly label: string };
  readonly action: string;
  readonly resource: { readonly type: string; readonly id: string | null };
  readonly projectId: string | null;
  readonly environmentId: string | null;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly metadata: Readonly<Record<string, SafeMetadataValue>>;
  readonly occurredAt: Date;
}

export interface AuditEventFilters {
  readonly actor?: string;
  readonly action?: string;
  readonly projectId?: string;
  readonly environmentId?: string;
  readonly from?: Date;
  readonly to?: Date;
  readonly resource?: string;
  readonly cursor?: string;
  readonly limit?: number;
}

export interface AuditEventPage {
  readonly events: readonly AuditEventView[];
  readonly nextCursor: string | null;
}

export interface AuditExport {
  readonly format: "csv" | "json";
  readonly filename: string;
  readonly mimeType: string;
  readonly content: string;
  readonly eventCount: number;
  readonly truncated: boolean;
}

interface AuditEventRow extends QueryResultRow {
  id: string;
  actor_type: AuditActor["type"];
  actor_user_id: string | null;
  actor_api_key_id: string | null;
  actor_label: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  project_id: string | null;
  environment_id: string | null;
  ip: string | null;
  user_agent: string | null;
  metadata: Record<string, SafeMetadataValue>;
  occurred_at: Date;
}

export class TransactionalAuditLog {
  readonly #pool: Pool;

  constructor(pool: Pool) {
    this.#pool = pool;
  }

  async execute<T>(
    event: AuditEventInput,
    operation: (transaction: AuditTransaction) => Promise<T>,
  ): Promise<T> {
    validateEvent(event);
    const metadata = metadataFor(event);
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const result = await operation(client);
      await this.#insert(client, event, metadata);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async record(event: AuditEventInput): Promise<void> {
    await this.execute(event, async () => undefined);
  }

  async recordInTransaction(
    transaction: AuditTransaction,
    event: AuditEventInput,
  ): Promise<void> {
    validateEvent(event);
    await this.#insert(transaction, event, metadataFor(event));
  }

  async list(
    transaction: AuditTransaction,
    orgId: string,
    filters: AuditEventFilters = {},
  ): Promise<AuditEventPage> {
    return this.#query(transaction, orgId, filters, 100);
  }

  async export(
    transaction: AuditTransaction,
    orgId: string,
    format: "csv" | "json",
    filters: Omit<AuditEventFilters, "cursor" | "limit"> = {},
  ): Promise<AuditExport> {
    const page = await this.#query(transaction, orgId, { ...filters, limit: 10_000 }, 10_000);
    const truncated = page.nextCursor !== null;
    const stamp = new Date().toISOString().slice(0, 10);
    if (format === "json") {
      return {
        format,
        filename: `himitsu-audit-${stamp}.json`,
        mimeType: "application/json",
        content: JSON.stringify(page.events, null, 2),
        eventCount: page.events.length,
        truncated,
      };
    }
    const columns = ["id", "occurred_at", "actor_type", "actor_id", "actor_label", "action", "resource_type", "resource_id", "project_id", "environment_id", "ip", "user_agent", "metadata"];
    const rows = page.events.map((event) => [
      event.id, event.occurredAt.toISOString(), event.actor.type, event.actor.id, event.actor.label,
      event.action, event.resource.type, event.resource.id, event.projectId, event.environmentId,
      event.ip, event.userAgent, JSON.stringify(event.metadata),
    ]);
    return {
      format,
      filename: `himitsu-audit-${stamp}.csv`,
      mimeType: "text/csv; charset=utf-8",
      content: [columns, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n",
      eventCount: page.events.length,
      truncated,
    };
  }

  async getRetention(transaction: AuditTransaction, orgId: string): Promise<number> {
    const result = await transaction.query<{ audit_retention_days: number }>(
      "SELECT audit_retention_days FROM organizations WHERE id = $1 AND deleted_at IS NULL",
      [orgId],
    );
    const days = result.rows[0]?.audit_retention_days;
    if (days === undefined) throw new AuditError("INVALID_EVENT", "Organization not found");
    return days;
  }

  async updateRetention(
    transaction: AuditTransaction,
    orgId: string,
    actorUserId: string,
    days: number,
  ): Promise<number> {
    if (!Number.isSafeInteger(days) || days < 1 || days > 3650) {
      throw new AuditError("INVALID_EVENT", "Audit retention must be between 1 and 3650 days");
    }
    const before = await this.getRetention(transaction, orgId);
    const updated = await transaction.query<{ audit_retention_days: number }>(
      "UPDATE organizations SET audit_retention_days = $1, updated_at = now() WHERE id = $2 RETURNING audit_retention_days",
      [days, orgId],
    );
    const saved = updated.rows[0]?.audit_retention_days;
    if (saved === undefined) throw new AuditError("INVALID_EVENT", "Organization not found");
    await this.recordInTransaction(transaction, {
      orgId,
      actor: { type: "user", id: actorUserId },
      action: "organization.audit_retention_updated",
      resource: { type: "organization", id: orgId },
      before: { auditRetentionDays: before },
      after: { auditRetentionDays: saved },
    });
    return saved;
  }

  async #query(
    transaction: AuditTransaction,
    orgId: string,
    filters: AuditEventFilters,
    maximumLimit: number,
  ): Promise<AuditEventPage> {
    const limit = filters.limit ?? 50;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > maximumLimit) {
      throw new AuditError("INVALID_EVENT", `Audit page limit must be between 1 and ${maximumLimit}`);
    }
    if (filters.from !== undefined && !Number.isFinite(filters.from.getTime())) throw new AuditError("INVALID_EVENT", "Audit from date is invalid");
    if (filters.to !== undefined && !Number.isFinite(filters.to.getTime())) throw new AuditError("INVALID_EVENT", "Audit to date is invalid");
    if (filters.from !== undefined && filters.to !== undefined && filters.from > filters.to) throw new AuditError("INVALID_EVENT", "Audit from date must not follow to date");
    const values: unknown[] = [orgId];
    const clauses = ["event.org_id = $1"];
    const bind = (value: unknown): string => { values.push(value); return `$${values.length}`; };
    if (filters.actor !== undefined && filters.actor.trim() !== "") {
      const actor = filters.actor.trim();
      const parameter = bind(`%${actor}%`);
      clauses.push(`(event.actor_type::text ILIKE ${parameter} OR event.actor_user_id::text ILIKE ${parameter} OR event.actor_api_key_id::text ILIKE ${parameter} OR "user".email ILIKE ${parameter} OR api_key.name ILIKE ${parameter} OR api_key.prefix ILIKE ${parameter})`);
    }
    if (filters.action !== undefined && filters.action !== "") clauses.push(`event.action = ${bind(filters.action)}`);
    if (filters.projectId !== undefined) clauses.push(`event.project_id = ${bind(filters.projectId)}`);
    if (filters.environmentId !== undefined) clauses.push(`event.environment_id = ${bind(filters.environmentId)}`);
    if (filters.from !== undefined) clauses.push(`event.occurred_at >= ${bind(filters.from)}`);
    if (filters.to !== undefined) clauses.push(`event.occurred_at <= ${bind(filters.to)}`);
    if (filters.resource !== undefined && filters.resource.trim() !== "") {
      const parameter = bind(`%${filters.resource.trim()}%`);
      clauses.push(`(event.resource_type ILIKE ${parameter} OR COALESCE(event.resource_id, '') ILIKE ${parameter})`);
    }
    if (filters.cursor !== undefined) {
      const cursor = decodeCursor(filters.cursor);
      clauses.push(`(event.occurred_at, event.id) < (${bind(cursor.occurredAt)}::timestamptz, ${bind(cursor.id)}::bigint)`);
    }
    values.push(limit + 1);
    const result = await transaction.query<AuditEventRow>(
      `SELECT event.id::text, event.actor_type, event.actor_user_id, event.actor_api_key_id,
              COALESCE("user".email, api_key.name, 'System') AS actor_label,
              event.action, event.resource_type, event.resource_id, event.project_id,
              event.environment_id, host(event.ip) AS ip, event.user_agent, event.metadata, event.occurred_at
       FROM audit_events event
       LEFT JOIN users "user" ON "user".id = event.actor_user_id
       LEFT JOIN api_keys api_key ON api_key.id = event.actor_api_key_id AND api_key.org_id = event.org_id
       WHERE ${clauses.join(" AND ")}
       ORDER BY event.occurred_at DESC, event.id DESC LIMIT $${values.length}`,
      values,
    );
    const hasMore = result.rows.length > limit;
    const rows = hasMore ? result.rows.slice(0, limit) : result.rows;
    const events = rows.map(eventFromRow);
    const last = events.at(-1);
    return { events, nextCursor: hasMore && last !== undefined ? encodeCursor(last) : null };
  }

  async #insert(
    client: AuditTransaction,
    event: AuditEventInput,
    metadata: Record<string, SafeMetadataValue>,
  ): Promise<void> {
    const actorUserId = event.actor.type === "user" ? event.actor.id : null;
    const actorApiKeyId = event.actor.type === "api_key" ? event.actor.id : null;
    await client.query(
      `INSERT INTO audit_events
        (org_id, actor_type, actor_user_id, actor_api_key_id, action, resource_type,
         resource_id, project_id, environment_id, ip, user_agent, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        event.orgId,
        event.actor.type,
        actorUserId,
        actorApiKeyId,
        event.action,
        event.resource.type,
        event.resource.id ?? null,
        event.projectId ?? null,
        event.environmentId ?? null,
        event.ip ?? null,
        event.userAgent ?? null,
        metadata,
      ],
    );
  }
}

function eventFromRow(row: AuditEventRow): AuditEventView {
  return {
    id: row.id,
    actor: { type: row.actor_type, id: row.actor_user_id ?? row.actor_api_key_id, label: row.actor_label },
    action: row.action,
    resource: { type: row.resource_type, id: row.resource_id },
    projectId: row.project_id,
    environmentId: row.environment_id,
    ip: row.ip,
    userAgent: row.user_agent,
    metadata: row.metadata,
    occurredAt: row.occurred_at,
  };
}

function encodeCursor(event: Pick<AuditEventView, "id" | "occurredAt">): string {
  return Buffer.from(JSON.stringify({ occurredAt: event.occurredAt.toISOString(), id: event.id }), "utf8").toString("base64url");
}

function decodeCursor(cursor: string): { occurredAt: Date; id: string } {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { occurredAt?: unknown; id?: unknown };
    const occurredAt = new Date(typeof parsed.occurredAt === "string" ? parsed.occurredAt : Number.NaN);
    if (!Number.isFinite(occurredAt.getTime()) || typeof parsed.id !== "string" || !/^[1-9][0-9]*$/.test(parsed.id)) throw new Error("invalid");
    return { occurredAt, id: parsed.id };
  } catch {
    throw new AuditError("INVALID_EVENT", "Audit cursor is invalid");
  }
}

function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}
