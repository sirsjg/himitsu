import type { Pool, QueryResult, QueryResultRow } from "pg";

export type AuditAction =
  | "organization.created"
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
