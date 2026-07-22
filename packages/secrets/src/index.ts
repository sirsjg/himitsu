import { randomUUID } from "node:crypto";
import type { AuditEventInput, AuditTransaction, TransactionalAuditLog } from "@himitsu/audit";
import { AuthorizationContextResolver, requirePermission } from "@himitsu/authz";
import {
  EnvelopeEncryptionService,
  PostgresTransactionDataKeyStore,
  type EncryptedSecretValue,
  type KeyWrapper,
} from "@himitsu/crypto";
import type { TenantTransaction } from "@himitsu/tenancy";

const MAX_VALUE_BYTES = 64 * 1024;
const MAX_BULK_ITEMS = 100;
const conventionalKey = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;

export class SecretError extends Error {
  readonly code:
    | "INVALID_INPUT"
    | "KEY_CONVENTION"
    | "VALUE_TOO_LARGE"
    | "KEY_EXISTS"
    | "VERSION_CONFLICT"
    | "NOT_FOUND";

  constructor(code: SecretError["code"], message: string) {
    super(message);
    this.name = "SecretError";
    this.code = code;
  }
}

export interface SecretMetadata {
  readonly id: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly key: string;
  readonly notes: string | null;
  readonly currentVersion: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface SecretWithValue extends SecretMetadata {
  readonly value: string;
}

export interface SecretVersionMetadata {
  readonly version: number;
  readonly authorUserId: string | null;
  readonly changeNote: string | null;
  readonly encryptionKeyVersion: number;
  readonly createdAt: Date;
  readonly current: boolean;
}

export interface SetSecretInput {
  readonly key: string;
  readonly value: string;
  readonly notes?: string | null;
  readonly changeNote?: string | null;
  readonly allowNonConformingKey?: boolean;
}

export type SecretImportStrategy = "skip" | "overwrite" | "merge";

export interface SecretImportResult {
  readonly secrets: readonly SecretMetadata[];
  readonly summary: {
    readonly requested: number;
    readonly created: number;
    readonly updated: number;
    readonly skipped: number;
  };
}

interface SecretRow {
  id: string;
  org_id: string;
  project_id: string;
  environment_id: string;
  key: string;
  notes: string | null;
  current_version: number;
  created_at: Date;
  updated_at: Date;
}

interface SecretValueRow extends SecretRow {
  value_ciphertext: Buffer;
  nonce: Buffer;
  auth_tag: Buffer;
  encryption_key_version: number;
}

interface AuditRecorder {
  recordInTransaction(transaction: AuditTransaction, event: AuditEventInput): Promise<void>;
}

export function validateSecretKey(key: string, allowNonConforming = false): string {
  const normalized = key.trim();
  if (
    normalized.length < 1
    || normalized.length > 255
    || /[\s=\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw new SecretError("INVALID_INPUT", "Secret keys must be 1-255 characters without whitespace, controls, or equals");
  }
  if (!allowNonConforming && !conventionalKey.test(normalized)) {
    throw new SecretError(
      "KEY_CONVENTION",
      "Secret keys should use UPPERCASE_SNAKE_CASE; explicitly override to retain another format",
    );
  }
  return normalized;
}

export function validateSecretValue(value: string): Buffer {
  const encoded = Buffer.from(value, "utf8");
  if (encoded.byteLength > MAX_VALUE_BYTES) {
    encoded.fill(0);
    throw new SecretError("VALUE_TOO_LARGE", "Secret values cannot exceed 64 KiB when UTF-8 encoded");
  }
  return encoded;
}

function validateNotes(notes: string | null | undefined): string | null {
  if (notes === null || notes === undefined || notes.trim() === "") return null;
  const normalized = notes.trim();
  if (normalized.length > 4000) throw new SecretError("INVALID_INPUT", "Secret notes cannot exceed 4000 characters");
  return normalized;
}

function validateChangeNote(changeNote: string | null | undefined): string | null {
  if (changeNote === null || changeNote === undefined || changeNote.trim() === "") return null;
  const normalized = changeNote.trim();
  if (normalized.length > 1000) throw new SecretError("INVALID_INPUT", "Change notes cannot exceed 1000 characters");
  return normalized;
}

function metadataFromRow(row: SecretRow): SecretMetadata {
  return {
    id: row.id,
    orgId: row.org_id,
    projectId: row.project_id,
    environmentId: row.environment_id,
    key: row.key,
    notes: row.notes,
    currentVersion: row.current_version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class SecretService {
  readonly #resolver: AuthorizationContextResolver;
  readonly #audit: AuditRecorder;
  readonly #wrapper: KeyWrapper;

  constructor(
    resolver: AuthorizationContextResolver,
    audit: TransactionalAuditLog,
    wrapper: KeyWrapper,
  ) {
    this.#resolver = resolver;
    this.#audit = audit;
    this.#wrapper = wrapper;
  }

  async list(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    environmentId: string,
  ): Promise<readonly SecretMetadata[]> {
    const environment = await this.#environment(transaction, projectId, environmentId);
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId, environment.protected),
      "secret.read",
    );
    const result = await transaction.query<SecretRow>(
      `${secretSelect}
       WHERE s.project_id = $1 AND s.environment_id = $2 AND s.deleted_at IS NULL
       ORDER BY s.key, s.id`,
      [projectId, environmentId],
    );
    return result.rows.map(metadataFromRow);
  }

  async get(
    transaction: TenantTransaction,
    actorUserId: string,
    secretId: string,
  ): Promise<SecretWithValue> {
    const row = await this.#valueRow(transaction, secretId);
    const environment = await this.#environment(transaction, row.project_id, row.environment_id);
    requirePermission(
      await this.#resolver.resolve(
        transaction,
        actorUserId,
        row.project_id,
        environment.protected,
      ),
      "secret.read",
    );
    const encryption = this.#encryption(transaction);
    const plaintext = await encryption.decrypt(this.#encrypted(row), {
      orgId: row.org_id,
      projectId: row.project_id,
      environmentId: row.environment_id,
      secretId: row.id,
      recordVersion: row.current_version,
    });
    try {
      const secret = { ...metadataFromRow(row), value: plaintext.toString("utf8") };
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: { type: "user", id: actorUserId },
        action: "secret.read",
        resource: { type: "secret", id: row.id },
        projectId: row.project_id,
        environmentId: row.environment_id,
        details: { key: row.key, version: row.current_version },
      });
      return secret;
    } finally {
      plaintext.fill(0);
      encryption.clearKeyCache();
    }
  }

  async listVersions(
    transaction: TenantTransaction,
    actorUserId: string,
    secretId: string,
  ): Promise<readonly SecretVersionMetadata[]> {
    const secret = await this.#metadataRow(transaction, secretId);
    const environment = await this.#environment(transaction, secret.project_id, secret.environment_id);
    requirePermission(
      await this.#resolver.resolve(
        transaction,
        actorUserId,
        secret.project_id,
        environment.protected,
      ),
      "secret.read",
    );
    const result = await transaction.query<{
      version: number;
      author_user_id: string | null;
      change_note: string | null;
      encryption_key_version: number;
      created_at: Date;
    }>(
      `SELECT version, author_user_id, change_note, encryption_key_version, created_at
       FROM secret_versions WHERE secret_id = $1 ORDER BY version DESC`,
      [secretId],
    );
    return result.rows.map((row) => ({
      version: row.version,
      authorUserId: row.author_user_id,
      changeNote: row.change_note,
      encryptionKeyVersion: row.encryption_key_version,
      createdAt: row.created_at,
      current: row.version === secret.current_version,
    }));
  }

  async create(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    environmentId: string,
    input: SetSecretInput,
  ): Promise<SecretMetadata> {
    return this.#create(transaction, actorUserId, projectId, environmentId, input);
  }

  async update(
    transaction: TenantTransaction,
    actorUserId: string,
    secretId: string,
    input: { value: string; notes?: string | null; changeNote?: string | null; expectedVersion?: number },
  ): Promise<SecretMetadata> {
    const before = await this.#metadataRow(transaction, secretId, true);
    const environment = await this.#environment(transaction, before.project_id, before.environment_id);
    requirePermission(
      await this.#resolver.resolve(
        transaction,
        actorUserId,
        before.project_id,
        environment.protected,
      ),
      "secret.write",
    );
    if (input.expectedVersion !== undefined && input.expectedVersion !== before.current_version) {
      throw new SecretError(
        "VERSION_CONFLICT",
        `Secret is at version ${before.current_version}; refresh before replacing version ${input.expectedVersion}`,
      );
    }
    return this.#writeVersion(transaction, actorUserId, before, input, "secret.updated");
  }

  async bulkSet(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    environmentId: string,
    inputs: readonly SetSecretInput[],
  ): Promise<readonly SecretMetadata[]> {
    if (inputs.length < 1 || inputs.length > MAX_BULK_ITEMS) {
      throw new SecretError("INVALID_INPUT", `Bulk writes require between 1 and ${MAX_BULK_ITEMS} secrets`);
    }
    const normalizedKeys = inputs.map((input) =>
      validateSecretKey(input.key, input.allowNonConformingKey ?? false),
    );
    if (new Set(normalizedKeys).size !== normalizedKeys.length) {
      throw new SecretError("INVALID_INPUT", "Bulk writes cannot contain duplicate keys");
    }
    const environment = await this.#environment(transaction, projectId, environmentId);
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId, environment.protected),
      "secret.write",
    );
    const results: SecretMetadata[] = [];
    for (const [index, input] of inputs.entries()) {
      const key = normalizedKeys[index];
      if (key === undefined) throw new Error("Normalized bulk key is missing");
      const existing = await transaction.query<SecretRow>(
        `${secretSelect}
         WHERE s.project_id = $1 AND s.environment_id = $2 AND s.key = $3 AND s.deleted_at IS NULL
         FOR UPDATE OF s`,
        [projectId, environmentId, key],
      );
      const row = existing.rows[0];
      if (row === undefined) {
        results.push(await this.#create(
          transaction,
          actorUserId,
          projectId,
          environmentId,
          { ...input, key },
          true,
        ));
      } else {
        results.push(await this.#writeVersion(transaction, actorUserId, row, input, "secret.updated"));
      }
    }
    return results;
  }

  async importBatch(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    environmentId: string,
    inputs: readonly SetSecretInput[],
    strategy: SecretImportStrategy,
    selectedKeys: readonly string[] = [],
  ): Promise<SecretImportResult> {
    if (inputs.length < 1 || inputs.length > MAX_BULK_ITEMS) {
      throw new SecretError("INVALID_INPUT", `Imports require between 1 and ${MAX_BULK_ITEMS} secrets`);
    }
    if (!(["skip", "overwrite", "merge"] as const).includes(strategy)) {
      throw new SecretError("INVALID_INPUT", "Import conflict strategy is invalid");
    }
    const normalized = inputs.map((input) => ({
      input,
      key: validateSecretKey(input.key, input.allowNonConformingKey ?? false),
    }));
    const sourceKeys = new Set(normalized.map(({ key }) => key));
    if (sourceKeys.size !== normalized.length) {
      throw new SecretError("INVALID_INPUT", "Imports cannot contain duplicate keys");
    }
    const selected = new Set(selectedKeys);
    if (strategy === "merge" && (selected.size === 0 || [...selected].some((key) => !sourceKeys.has(key)))) {
      throw new SecretError("INVALID_INPUT", "Merge imports require selected keys from the preview");
    }
    const environment = await this.#environment(transaction, projectId, environmentId);
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId, environment.protected),
      "secret.write",
    );
    const existingRows = await transaction.query<SecretRow>(
      `${secretSelect}
       WHERE s.project_id = $1 AND s.environment_id = $2 AND s.key = ANY($3::text[])
         AND s.deleted_at IS NULL
       ORDER BY s.key
       FOR UPDATE OF s`,
      [projectId, environmentId, [...sourceKeys]],
    );
    const existing = new Map(existingRows.rows.map((row) => [row.key, row]));
    const results: SecretMetadata[] = [];
    let created = 0;
    let updated = 0;
    let skipped = 0;
    for (const { input, key } of normalized) {
      const row = existing.get(key);
      const included = strategy === "overwrite"
        || (strategy === "skip" && row === undefined)
        || (strategy === "merge" && selected.has(key));
      if (!included) { skipped += 1; continue; }
      if (row === undefined) {
        results.push(await this.#create(
          transaction,
          actorUserId,
          projectId,
          environmentId,
          { ...input, key, changeNote: input.changeNote ?? "dotenv import" },
          true,
          false,
        ));
        created += 1;
      } else {
        results.push(await this.#writeVersion(
          transaction,
          actorUserId,
          row,
          { ...input, changeNote: input.changeNote ?? "dotenv import" },
          "secret.updated",
          false,
        ));
        updated += 1;
      }
    }
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "secret.imported",
      resource: { type: "environment", id: environmentId },
      projectId,
      environmentId,
      details: {
        format: "dotenv",
        strategy,
        requested: normalized.length,
        created,
        updated,
        skipped,
        keys: results.map(({ key }) => key),
      },
    });
    return { secrets: results, summary: { requested: normalized.length, created, updated, skipped } };
  }

  async delete(
    transaction: TenantTransaction,
    actorUserId: string,
    secretId: string,
  ): Promise<SecretMetadata> {
    const row = await this.#metadataRow(transaction, secretId, true);
    const environment = await this.#environment(transaction, row.project_id, row.environment_id);
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, row.project_id, environment.protected),
      "secret.delete",
    );
    await transaction.query(
      "UPDATE secrets SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL",
      [secretId],
    );
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "secret.deleted",
      resource: { type: "secret", id: secretId },
      projectId: row.project_id,
      environmentId: row.environment_id,
      before: { key: row.key, version: row.current_version },
    });
    return metadataFromRow(row);
  }

  async #create(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    environmentId: string,
    input: SetSecretInput,
    authorized = false,
    recordAudit = true,
  ): Promise<SecretMetadata> {
    const environment = await this.#environment(transaction, projectId, environmentId);
    if (!authorized) {
      requirePermission(
        await this.#resolver.resolve(transaction, actorUserId, projectId, environment.protected),
        "secret.write",
      );
    }
    const key = validateSecretKey(input.key, input.allowNonConformingKey ?? false);
    const notes = validateNotes(input.notes);
    const changeNote = validateChangeNote(input.changeNote);
    const deleted = await transaction.query<SecretRow>(
      `${secretSelect}
       WHERE s.project_id = $1 AND s.environment_id = $2 AND s.key = $3
         AND s.deleted_at IS NOT NULL
         AND s.deleted_by_project_at IS NULL
         AND s.deleted_by_environment_at IS NULL
       FOR UPDATE OF s`,
      [projectId, environmentId, key],
    );
    const recoverable = deleted.rows[0];
    if (recoverable !== undefined) {
      await transaction.query(
        "UPDATE secrets SET deleted_at = NULL, updated_at = now() WHERE id = $1",
        [recoverable.id],
      );
      return this.#writeVersion(
        transaction,
        actorUserId,
        recoverable,
        { value: input.value, notes, changeNote },
        "secret.created",
        recordAudit,
      );
    }
    const secretId = randomUUID();
    try {
      const inserted = await transaction.query<SecretRow>(
        `INSERT INTO secrets
          (id, org_id, project_id, environment_id, key, notes, current_version, created_by_user_id)
         VALUES ($1, $2, $3, $4, $5, $6, 0, $7)
         RETURNING id, org_id, project_id, environment_id, key, notes,
                   current_version, created_at, updated_at`,
        [secretId, transaction.orgId, projectId, environmentId, key, notes, actorUserId],
      );
      const row = inserted.rows[0];
      if (row === undefined) throw new Error("Secret insertion returned no row");
      return await this.#writeVersion(
        transaction,
        actorUserId,
        row,
        { value: input.value, notes, changeNote },
        "secret.created",
        recordAudit,
      );
    } catch (error) {
      if ((error as { code?: string }).code === "23505") {
        throw new SecretError("KEY_EXISTS", "Secret key already exists in this environment");
      }
      throw error;
    }
  }

  async #writeVersion(
    transaction: TenantTransaction,
    actorUserId: string,
    before: SecretRow,
    input: { value: string; notes?: string | null; changeNote?: string | null },
    action: "secret.created" | "secret.updated",
    recordAudit = true,
  ): Promise<SecretMetadata> {
    const plaintext = validateSecretValue(input.value);
    const notes = input.notes === undefined ? before.notes : validateNotes(input.notes);
    const changeNote = validateChangeNote(input.changeNote);
    const nextVersion = before.current_version + 1;
    const encryption = this.#encryption(transaction);
    try {
      const encrypted = await encryption.encrypt(plaintext, {
        orgId: before.org_id,
        projectId: before.project_id,
        environmentId: before.environment_id,
        secretId: before.id,
        recordVersion: nextVersion,
      });
      await transaction.query(
        `INSERT INTO secret_versions
          (org_id, project_id, environment_id, secret_id, version, value_ciphertext,
           nonce, auth_tag, encryption_key_version, author_user_id, change_note)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          before.org_id,
          before.project_id,
          before.environment_id,
          before.id,
          nextVersion,
          encrypted.ciphertext,
          encrypted.nonce,
          encrypted.authTag,
          encrypted.keyVersion,
          actorUserId,
          changeNote,
        ],
      );
      const updated = await transaction.query<SecretRow>(
        `UPDATE secrets SET current_version = $1, notes = $2, updated_at = now()
         WHERE id = $3 AND deleted_at IS NULL
         RETURNING id, org_id, project_id, environment_id, key, notes,
                   current_version, created_at, updated_at`,
        [nextVersion, notes, before.id],
      );
      const row = updated.rows[0];
      if (row === undefined) throw new SecretError("NOT_FOUND", "Secret not found");
      if (recordAudit) {
        await this.#audit.recordInTransaction(transaction, {
          orgId: transaction.orgId,
          actor: { type: "user", id: actorUserId },
          action,
          resource: { type: "secret", id: row.id },
          projectId: row.project_id,
          environmentId: row.environment_id,
          ...(action === "secret.updated"
            ? { before: { key: before.key, version: before.current_version, notesPresent: before.notes !== null } }
            : {}),
          after: { key: row.key, version: row.current_version, notesPresent: row.notes !== null },
        });
      }
      return metadataFromRow(row);
    } finally {
      plaintext.fill(0);
      encryption.clearKeyCache();
    }
  }

  async #metadataRow(
    transaction: TenantTransaction,
    secretId: string,
    lock = false,
  ): Promise<SecretRow> {
    const result = await transaction.query<SecretRow>(
      `${secretSelect} WHERE s.id = $1 AND s.deleted_at IS NULL ${lock ? "FOR UPDATE OF s" : ""}`,
      [secretId],
    );
    const row = result.rows[0];
    if (row === undefined) throw new SecretError("NOT_FOUND", "Secret not found");
    return row;
  }

  async #valueRow(transaction: TenantTransaction, secretId: string): Promise<SecretValueRow> {
    const result = await transaction.query<SecretValueRow>(
      `SELECT ${secretColumns}, sv.value_ciphertext, sv.nonce, sv.auth_tag, sv.encryption_key_version
       FROM secrets s
       JOIN secret_versions sv
         ON sv.org_id = s.org_id AND sv.secret_id = s.id AND sv.version = s.current_version
       WHERE s.id = $1 AND s.deleted_at IS NULL`,
      [secretId],
    );
    const row = result.rows[0];
    if (row === undefined) throw new SecretError("NOT_FOUND", "Secret not found");
    return row;
  }

  async #environment(
    transaction: TenantTransaction,
    projectId: string,
    environmentId: string,
  ): Promise<{ protected: boolean }> {
    const result = await transaction.query<{ protected: boolean }>(
      `SELECT e.protected
       FROM environments e JOIN projects p ON p.id = e.project_id AND p.org_id = e.org_id
       WHERE e.id = $1 AND e.project_id = $2
         AND e.deleted_at IS NULL AND p.deleted_at IS NULL`,
      [environmentId, projectId],
    );
    const row = result.rows[0];
    if (row === undefined) throw new SecretError("NOT_FOUND", "Environment not found");
    return row;
  }

  #encryption(transaction: TenantTransaction): EnvelopeEncryptionService {
    return new EnvelopeEncryptionService(
      new PostgresTransactionDataKeyStore(transaction),
      this.#wrapper,
      { cacheTtlMs: 0, maxCacheEntries: 1 },
    );
  }

  #encrypted(row: SecretValueRow): EncryptedSecretValue {
    return {
      algorithm: "aes-256-gcm",
      keyVersion: row.encryption_key_version,
      ciphertext: row.value_ciphertext,
      nonce: row.nonce,
      authTag: row.auth_tag,
    };
  }
}

const secretColumns = `s.id, s.org_id, s.project_id, s.environment_id, s.key,
  s.notes, s.current_version, s.created_at, s.updated_at`;
const secretSelect = `SELECT ${secretColumns} FROM secrets s`;
