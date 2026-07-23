import { randomUUID, timingSafeEqual } from "node:crypto";
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
    | "VERSION_NOT_FOUND"
    | "TAG_NOT_FOUND"
    | "NOT_FOUND";

  constructor(code: SecretError["code"], message: string) {
    super(message);
    this.name = "SecretError";
    this.code = code;
  }
}

export interface SecretTag {
  readonly id: string;
  readonly name: string;
  readonly color: string;
}

export interface SecretMetadata {
  readonly id: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly key: string;
  readonly notes: string | null;
  readonly tagIds: readonly string[];
  readonly tags: readonly SecretTag[];
  readonly currentVersion: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface SecretWithValue extends SecretMetadata {
  readonly value: string;
}

export interface RuntimeSecretConfig {
  readonly configVersion: number;
  readonly notModified: boolean;
  readonly secrets?: Readonly<Record<string, string>>;
}

export type SecretExportFormat = "dotenv" | "json" | "shell";

export interface SecretExportResult {
  readonly format: SecretExportFormat;
  readonly filename: string;
  readonly mimeType: string;
  readonly content: string;
  readonly secretCount: number;
  readonly nested: boolean;
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
  readonly tagIds?: readonly string[];
}

export type SecretImportStrategy = "skip" | "overwrite" | "merge";
export type SecretImportFormat = "dotenv" | "json";

export interface SecretImportResult {
  readonly secrets: readonly SecretMetadata[];
  readonly summary: {
    readonly requested: number;
    readonly created: number;
    readonly updated: number;
    readonly skipped: number;
  };
}

export interface SecretPromotionPreviewItem {
  readonly key: string;
  readonly action: "create" | "overwrite";
  readonly changed: boolean;
  readonly sourceVersion: number;
  readonly targetVersion: number | null;
}

export interface SecretPromotionPreview {
  readonly sourceEnvironmentId: string;
  readonly targetEnvironmentId: string;
  readonly items: readonly SecretPromotionPreviewItem[];
  readonly summary: { readonly selected: number; readonly created: number; readonly overwritten: number };
}

export interface SecretPromotionResult extends SecretPromotionPreview {
  readonly secrets: readonly SecretMetadata[];
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
  tag_ids?: string[] | null;
  tags?: SecretTag[] | null;
}

interface SecretValueRow extends SecretRow {
  value_ciphertext: Buffer;
  nonce: Buffer;
  auth_tag: Buffer;
  encryption_key_version: number;
}

interface SecretVersionValueRow extends SecretValueRow {
  record_version: number;
}

export interface SecretVersionComparison {
  readonly fromVersion: number;
  readonly toVersion: number;
  readonly changed: boolean;
  readonly masked: boolean;
  readonly fromValue?: string;
  readonly toValue?: string;
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

function exportableKey(key: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    throw new SecretError("INVALID_INPUT", `Secret key ${key} cannot be represented in dotenv or shell format`);
  }
  return key;
}

export function serializeSecretExport(
  secrets: Readonly<Record<string, string>>,
  format: SecretExportFormat,
  options: { nested?: boolean; delimiter?: string } = {},
): string {
  const entries = Object.entries(secrets).sort(([left], [right]) => left.localeCompare(right));
  if (format === "dotenv") {
    return entries.map(([key, value]) => `${exportableKey(key)}=${JSON.stringify(value)}`).join("\n")
      + (entries.length === 0 ? "" : "\n");
  }
  if (format === "shell") {
    return entries.map(([key, value]) => `export ${exportableKey(key)}='${value.replaceAll("'", "'\\''")}'`).join("\n")
      + (entries.length === 0 ? "" : "\n");
  }
  if (!options.nested) return JSON.stringify(Object.fromEntries(entries), null, 2) + "\n";
  const delimiter = options.delimiter ?? "__";
  if (delimiter.length < 1 || delimiter.length > 10) {
    throw new SecretError("INVALID_INPUT", "Nested JSON delimiters must be between 1 and 10 characters");
  }
  const root: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of entries) {
    const path = key.split(delimiter);
    if (path.some((segment) => segment === "")) {
      throw new SecretError("INVALID_INPUT", `Secret key ${key} has an empty nested JSON path segment`);
    }
    let cursor = root;
    for (const [index, segment] of path.entries()) {
      if (index === path.length - 1) {
        if (Object.hasOwn(cursor, segment)) {
          throw new SecretError("INVALID_INPUT", `Secret key ${key} conflicts with another nested JSON path`);
        }
        cursor[segment] = value;
        continue;
      }
      const existing = cursor[segment];
      if (existing === undefined) {
        const child: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
        cursor[segment] = child;
        cursor = child;
      } else if (typeof existing === "object" && existing !== null && !Array.isArray(existing)) {
        cursor = existing as Record<string, unknown>;
      } else {
        throw new SecretError("INVALID_INPUT", `Secret key ${key} conflicts with another nested JSON path`);
      }
    }
  }
  return JSON.stringify(root, null, 2) + "\n";
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
    tagIds: row.tag_ids ?? [],
    tags: row.tags ?? [],
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
    filters: { search?: string; tagId?: string } = {},
  ): Promise<readonly SecretMetadata[]> {
    const environment = await this.#environment(transaction, projectId, environmentId);
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId, environment.protected),
      "secret.read",
    );
    const search = filters.search?.trim() || null;
    const result = await transaction.query<SecretRow>(
      `${secretSelect}
       WHERE s.project_id = $1 AND s.environment_id = $2 AND s.deleted_at IS NULL
         AND ($3::text IS NULL OR s.key ILIKE '%' || $3 || '%' OR COALESCE(s.notes, '') ILIKE '%' || $3 || '%'
           OR EXISTS (
             SELECT 1 FROM secret_tags search_st
             JOIN tags search_t ON search_t.id = search_st.tag_id AND search_t.org_id = search_st.org_id
             WHERE search_st.secret_id = s.id AND search_st.org_id = s.org_id
               AND search_t.name ILIKE '%' || $3 || '%'
           ))
         AND ($4::uuid IS NULL OR EXISTS (
           SELECT 1 FROM secret_tags filter_st
           WHERE filter_st.secret_id = s.id AND filter_st.org_id = s.org_id AND filter_st.tag_id = $4
         ))
       ORDER BY s.key, s.id`,
      [projectId, environmentId, search, filters.tagId ?? null],
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

  async runtimeConfig(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    environmentId: string,
    knownVersions: readonly number[] | "*" = [],
    auditActor: AuditEventInput["actor"] = { type: "user", id: actorUserId },
  ): Promise<RuntimeSecretConfig> {
    const environment = await transaction.query<{ protected: boolean; config_version: string }>(
      `SELECT e.protected, e.config_version::text AS config_version
       FROM environments e JOIN projects p ON p.id = e.project_id AND p.org_id = e.org_id
       WHERE e.id = $1 AND e.project_id = $2
         AND e.deleted_at IS NULL AND p.deleted_at IS NULL`,
      [environmentId, projectId],
    );
    const scope = environment.rows[0];
    if (scope === undefined) throw new SecretError("NOT_FOUND", "Environment not found");
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId, scope.protected),
      "secret.read",
    );
    const configVersion = Number(scope.config_version);
    if (!Number.isSafeInteger(configVersion) || configVersion < 0) {
      throw new Error("Environment config version is outside the supported range");
    }
    if (knownVersions === "*" || knownVersions.includes(configVersion)) {
      return { configVersion, notModified: true };
    }

    const rows = await transaction.query<SecretValueRow>(
      `SELECT ${secretColumns}, sv.value_ciphertext, sv.nonce, sv.auth_tag, sv.encryption_key_version
       FROM secrets s
       JOIN secret_versions sv
         ON sv.org_id = s.org_id AND sv.secret_id = s.id AND sv.version = s.current_version
       WHERE s.project_id = $1 AND s.environment_id = $2 AND s.deleted_at IS NULL
       ORDER BY s.key, s.id`,
      [projectId, environmentId],
    );
    const encryption = this.#encryption(transaction);
    const plaintextBuffers: Buffer[] = [];
    try {
      const entries: Array<readonly [string, string]> = [];
      for (const row of rows.rows) {
        const plaintext = await encryption.decrypt(this.#encrypted(row), {
          orgId: row.org_id,
          projectId: row.project_id,
          environmentId: row.environment_id,
          secretId: row.id,
          recordVersion: row.current_version,
        });
        plaintextBuffers.push(plaintext);
        entries.push([row.key, plaintext.toString("utf8")]);
      }
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: auditActor,
        action: "secret.read",
        resource: { type: "environment", id: environmentId },
        projectId,
        environmentId,
        details: { count: entries.length, configVersion },
      });
      return { configVersion, notModified: false, secrets: Object.fromEntries(entries) };
    } finally {
      for (const plaintext of plaintextBuffers) plaintext.fill(0);
      encryption.clearKeyCache();
    }
  }

  async exportConfig(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    environmentId: string,
    format: SecretExportFormat,
    options: { nested?: boolean; delimiter?: string } = {},
    auditActor: AuditEventInput["actor"] = { type: "user", id: actorUserId },
  ): Promise<SecretExportResult> {
    const environment = await transaction.query<{
      protected: boolean;
      environment_slug: string;
      project_slug: string;
    }>(
      `SELECT e.protected, e.slug AS environment_slug, p.slug AS project_slug
       FROM environments e JOIN projects p ON p.id = e.project_id AND p.org_id = e.org_id
       WHERE e.id = $1 AND e.project_id = $2
         AND e.deleted_at IS NULL AND p.deleted_at IS NULL`,
      [environmentId, projectId],
    );
    const scope = environment.rows[0];
    if (scope === undefined) throw new SecretError("NOT_FOUND", "Environment not found");
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId, scope.protected),
      "secret.read",
    );
    if (!(format === "dotenv" || format === "json" || format === "shell")) {
      throw new SecretError("INVALID_INPUT", "Secret export format is invalid");
    }
    const rows = await transaction.query<SecretValueRow>(
      `SELECT ${secretColumns}, sv.value_ciphertext, sv.nonce, sv.auth_tag, sv.encryption_key_version
       FROM secrets s JOIN secret_versions sv
         ON sv.org_id = s.org_id AND sv.secret_id = s.id AND sv.version = s.current_version
       WHERE s.project_id = $1 AND s.environment_id = $2 AND s.deleted_at IS NULL
       ORDER BY s.key, s.id`,
      [projectId, environmentId],
    );
    const encryption = this.#encryption(transaction);
    const plaintextBuffers: Buffer[] = [];
    try {
      const entries: Array<readonly [string, string]> = [];
      for (const row of rows.rows) {
        const plaintext = await encryption.decrypt(this.#encrypted(row), {
          orgId: row.org_id,
          projectId: row.project_id,
          environmentId: row.environment_id,
          secretId: row.id,
          recordVersion: row.current_version,
        });
        plaintextBuffers.push(plaintext);
        entries.push([row.key, plaintext.toString("utf8")]);
      }
      const nested = format === "json" && (options.nested ?? false);
      const content = serializeSecretExport(Object.fromEntries(entries), format, options);
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: auditActor,
        action: "secret.exported",
        resource: { type: "environment", id: environmentId },
        projectId,
        environmentId,
        details: { format, nested, count: entries.length },
      });
      const extension = format === "dotenv" ? "env" : format === "shell" ? "sh" : "json";
      return {
        format,
        filename: `${scope.project_slug}-${scope.environment_slug}.${extension}`,
        mimeType: format === "json" ? "application/json" : "text/plain; charset=utf-8",
        content,
        secretCount: entries.length,
        nested,
      };
    } finally {
      for (const plaintext of plaintextBuffers) plaintext.fill(0);
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

  async compareVersions(
    transaction: TenantTransaction,
    actorUserId: string,
    secretId: string,
    fromVersion: number,
    toVersion: number,
    reveal = false,
  ): Promise<SecretVersionComparison> {
    if (!Number.isInteger(fromVersion) || fromVersion < 1 || !Number.isInteger(toVersion) || toVersion < 1) {
      throw new SecretError("INVALID_INPUT", "Version numbers must be positive integers");
    }
    const secret = await this.#metadataRow(transaction, secretId);
    const environment = await this.#environment(transaction, secret.project_id, secret.environment_id);
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, secret.project_id, environment.protected),
      "secret.read",
    );
    const rows = await transaction.query<SecretVersionValueRow>(
      `SELECT ${secretColumns}, sv.version AS record_version, sv.value_ciphertext,
              sv.nonce, sv.auth_tag, sv.encryption_key_version
       FROM secrets s
       JOIN secret_versions sv ON sv.org_id = s.org_id AND sv.secret_id = s.id
       WHERE s.id = $1 AND s.deleted_at IS NULL AND sv.version = ANY($2::integer[])
       ORDER BY sv.version`,
      [secretId, [...new Set([fromVersion, toVersion])]],
    );
    const byVersion = new Map(rows.rows.map((row) => [row.record_version, row]));
    const from = byVersion.get(fromVersion);
    const to = byVersion.get(toVersion);
    if (from === undefined || to === undefined) throw new SecretError("VERSION_NOT_FOUND", "Secret version not found");
    const encryption = this.#encryption(transaction);
    const fromPlaintext = await encryption.decrypt(this.#encrypted(from), this.#versionContext(from));
    const toPlaintext = fromVersion === toVersion
      ? Buffer.from(fromPlaintext)
      : await encryption.decrypt(this.#encrypted(to), this.#versionContext(to));
    try {
      const changed = fromPlaintext.length !== toPlaintext.length
        || !timingSafeEqual(fromPlaintext, toPlaintext);
      await this.#audit.recordInTransaction(transaction, {
        orgId: transaction.orgId,
        actor: { type: "user", id: actorUserId },
        action: "secret.read",
        resource: { type: "secret", id: secretId },
        projectId: secret.project_id,
        environmentId: secret.environment_id,
        details: { operation: "version_compare", fromVersion, toVersion, revealed: reveal, changed },
      });
      return {
        fromVersion,
        toVersion,
        changed,
        masked: !reveal,
        ...(reveal ? { fromValue: fromPlaintext.toString("utf8"), toValue: toPlaintext.toString("utf8") } : {}),
      };
    } finally {
      fromPlaintext.fill(0);
      toPlaintext.fill(0);
      encryption.clearKeyCache();
    }
  }

  async rollback(
    transaction: TenantTransaction,
    actorUserId: string,
    secretId: string,
    targetVersion: number,
    input: { expectedVersion?: number; changeNote?: string | null } = {},
  ): Promise<SecretMetadata> {
    if (!Number.isInteger(targetVersion) || targetVersion < 1) {
      throw new SecretError("INVALID_INPUT", "Rollback version must be a positive integer");
    }
    const before = await this.#metadataRow(transaction, secretId, true);
    const environment = await this.#environment(transaction, before.project_id, before.environment_id);
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, before.project_id, environment.protected),
      "secret.write",
    );
    if (input.expectedVersion !== undefined && input.expectedVersion !== before.current_version) {
      throw new SecretError("VERSION_CONFLICT", `Secret is at version ${before.current_version}; refresh before rolling back version ${input.expectedVersion}`);
    }
    if (targetVersion >= before.current_version) {
      throw new SecretError("INVALID_INPUT", "Rollback target must be an earlier version");
    }
    const target = await this.#versionValueRow(transaction, secretId, targetVersion);
    const encryption = this.#encryption(transaction);
    const plaintext = await encryption.decrypt(this.#encrypted(target), this.#versionContext(target));
    try {
      return await this.#writeVersion(
        transaction,
        actorUserId,
        before,
        { value: plaintext.toString("utf8"), changeNote: input.changeNote ?? `Rollback to version ${targetVersion}` },
        "secret.updated",
      );
    } finally {
      plaintext.fill(0);
      encryption.clearKeyCache();
    }
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
    input: { value: string; notes?: string | null; changeNote?: string | null; expectedVersion?: number; tagIds?: readonly string[] },
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
    format: SecretImportFormat = "dotenv",
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
          { ...input, key, changeNote: input.changeNote ?? `${format} import` },
          true,
          false,
        ));
        created += 1;
      } else {
        results.push(await this.#writeVersion(
          transaction,
          actorUserId,
          row,
          { ...input, changeNote: input.changeNote ?? `${format} import` },
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
        format,
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

  async previewPromotion(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    sourceEnvironmentId: string,
    targetEnvironmentId: string,
    keys?: readonly string[],
  ): Promise<SecretPromotionPreview> {
    const normalizedKeys = await this.#authorizePromotion(
      transaction, actorUserId, projectId, sourceEnvironmentId, targetEnvironmentId, keys,
    );
    const rows = await transaction.query<SecretValueRow>(
      `SELECT ${secretColumns}, sv.value_ciphertext, sv.nonce, sv.auth_tag, sv.encryption_key_version
       FROM secrets s
       JOIN secret_versions sv
         ON sv.org_id = s.org_id AND sv.secret_id = s.id AND sv.version = s.current_version
       WHERE s.project_id = $1 AND s.environment_id = ANY($2::uuid[])
         AND s.deleted_at IS NULL
         ${normalizedKeys === undefined ? "" : "AND s.key = ANY($3::text[])"}
       ORDER BY s.environment_id, s.key`,
      normalizedKeys === undefined
        ? [projectId, [sourceEnvironmentId, targetEnvironmentId]]
        : [projectId, [sourceEnvironmentId, targetEnvironmentId], normalizedKeys],
    );
    return this.#promotionPreview(transaction, rows.rows, sourceEnvironmentId, targetEnvironmentId, normalizedKeys);
  }

  async promote(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    sourceEnvironmentId: string,
    targetEnvironmentId: string,
    keys?: readonly string[],
  ): Promise<SecretPromotionResult> {
    const normalizedKeys = await this.#authorizePromotion(
      transaction, actorUserId, projectId, sourceEnvironmentId, targetEnvironmentId, keys,
    );
    const rows = await transaction.query<SecretValueRow>(
      `SELECT ${secretColumns}, sv.value_ciphertext, sv.nonce, sv.auth_tag, sv.encryption_key_version
       FROM secrets s
       JOIN secret_versions sv
         ON sv.org_id = s.org_id AND sv.secret_id = s.id AND sv.version = s.current_version
       WHERE s.project_id = $1 AND s.environment_id = ANY($2::uuid[])
         AND s.deleted_at IS NULL
         ${normalizedKeys === undefined ? "" : "AND s.key = ANY($3::text[])"}
       ORDER BY s.environment_id, s.key
       FOR UPDATE OF s`,
      normalizedKeys === undefined
        ? [projectId, [sourceEnvironmentId, targetEnvironmentId]]
        : [projectId, [sourceEnvironmentId, targetEnvironmentId], normalizedKeys],
    );
    const preview = await this.#promotionPreview(transaction, rows.rows, sourceEnvironmentId, targetEnvironmentId, normalizedKeys);
    const sources = rows.rows.filter(({ environment_id: environmentId }) => environmentId === sourceEnvironmentId);
    const targets = new Map(rows.rows
      .filter(({ environment_id: environmentId }) => environmentId === targetEnvironmentId)
      .map((row) => [row.key, row]));
    const promoted: SecretMetadata[] = [];
    for (const source of sources) {
      const sourceEncryption = this.#encryption(transaction);
      const plaintext = await sourceEncryption.decrypt(this.#encrypted(source), {
        orgId: source.org_id,
        projectId: source.project_id,
        environmentId: source.environment_id,
        secretId: source.id,
        recordVersion: source.current_version,
      });
      try {
        const input = {
          value: plaintext.toString("utf8"),
          notes: source.notes,
          changeNote: `Promoted from environment ${sourceEnvironmentId}`,
        };
        const target = targets.get(source.key);
        promoted.push(target === undefined
          ? await this.#create(transaction, actorUserId, projectId, targetEnvironmentId, {
            key: source.key, allowNonConformingKey: true, ...input,
          }, true, false)
          : await this.#writeVersion(transaction, actorUserId, target, input, "secret.updated", false));
      } finally {
        plaintext.fill(0);
        sourceEncryption.clearKeyCache();
      }
    }
    await this.#audit.recordInTransaction(transaction, {
      orgId: transaction.orgId,
      actor: { type: "user", id: actorUserId },
      action: "secret.promoted",
      resource: { type: "environment", id: targetEnvironmentId },
      projectId,
      environmentId: targetEnvironmentId,
      details: {
        sourceEnvironmentId,
        targetEnvironmentId,
        created: preview.summary.created,
        overwritten: preview.summary.overwritten,
        keys: preview.items.map(({ key }) => key),
      },
    });
    return { ...preview, secrets: promoted };
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
        { value: input.value, notes, changeNote, tagIds: input.tagIds ?? [] },
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
        { value: input.value, notes, changeNote, tagIds: input.tagIds ?? [] },
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
    input: { value: string; notes?: string | null; changeNote?: string | null; tagIds?: readonly string[] },
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
      if (input.tagIds !== undefined) await this.#replaceTags(transaction, row, input.tagIds);
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
      return metadataFromRow(await this.#metadataRow(transaction, row.id));
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

  async #replaceTags(
    transaction: TenantTransaction,
    secret: Pick<SecretRow, "id" | "project_id" | "environment_id">,
    tagIds: readonly string[],
  ): Promise<void> {
    const uniqueTagIds = [...new Set(tagIds)];
    if (uniqueTagIds.length > 50) throw new SecretError("INVALID_INPUT", "A secret can have at most 50 tags");
    if (uniqueTagIds.length > 0) {
      const found = await transaction.query<{ id: string }>(
        "SELECT id FROM tags WHERE id = ANY($1::uuid[])",
        [uniqueTagIds],
      );
      if (found.rowCount !== uniqueTagIds.length) {
        throw new SecretError("TAG_NOT_FOUND", "One or more secret tags do not exist in this organization");
      }
    }
    await transaction.query("DELETE FROM secret_tags WHERE secret_id = $1", [secret.id]);
    if (uniqueTagIds.length > 0) {
      await transaction.query(
        `INSERT INTO secret_tags (org_id, project_id, environment_id, secret_id, tag_id)
         SELECT $1, $2, $3, $4, unnest($5::uuid[])`,
        [transaction.orgId, secret.project_id, secret.environment_id, secret.id, uniqueTagIds],
      );
    }
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

  async #versionValueRow(
    transaction: TenantTransaction,
    secretId: string,
    version: number,
  ): Promise<SecretVersionValueRow> {
    const result = await transaction.query<SecretVersionValueRow>(
      `SELECT ${secretColumns}, sv.version AS record_version, sv.value_ciphertext,
              sv.nonce, sv.auth_tag, sv.encryption_key_version
       FROM secrets s
       JOIN secret_versions sv ON sv.org_id = s.org_id AND sv.secret_id = s.id
       WHERE s.id = $1 AND s.deleted_at IS NULL AND sv.version = $2`,
      [secretId, version],
    );
    const row = result.rows[0];
    if (row === undefined) throw new SecretError("VERSION_NOT_FOUND", "Secret version not found");
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

  async #authorizePromotion(
    transaction: TenantTransaction,
    actorUserId: string,
    projectId: string,
    sourceEnvironmentId: string,
    targetEnvironmentId: string,
    keys?: readonly string[],
  ): Promise<readonly string[] | undefined> {
    if (sourceEnvironmentId === targetEnvironmentId) {
      throw new SecretError("INVALID_INPUT", "Source and target environments must be different");
    }
    const normalizedKeys = keys?.map((key) => validateSecretKey(key, true));
    if (normalizedKeys !== undefined && (normalizedKeys.length < 1 || new Set(normalizedKeys).size !== normalizedKeys.length)) {
      throw new SecretError("INVALID_INPUT", "Selected promotion keys must be non-empty and unique");
    }
    const source = await this.#environment(transaction, projectId, sourceEnvironmentId);
    const target = await this.#environment(transaction, projectId, targetEnvironmentId);
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId, source.protected),
      "secret.read",
    );
    requirePermission(
      await this.#resolver.resolve(transaction, actorUserId, projectId, target.protected),
      "secret.write",
    );
    return normalizedKeys;
  }

  async #promotionPreview(
    transaction: TenantTransaction,
    rows: readonly SecretValueRow[],
    sourceEnvironmentId: string,
    targetEnvironmentId: string,
    selectedKeys?: readonly string[],
  ): Promise<SecretPromotionPreview> {
    const sources = rows.filter(({ environment_id: environmentId }) => environmentId === sourceEnvironmentId);
    const targets = new Map(rows
      .filter(({ environment_id: environmentId }) => environmentId === targetEnvironmentId)
      .map((row) => [row.key, row]));
    if (selectedKeys !== undefined) {
      const found = new Set(sources.map(({ key }) => key));
      const missing = selectedKeys.filter((key) => !found.has(key));
      if (missing.length > 0) throw new SecretError("NOT_FOUND", `Source secrets not found: ${missing.join(", ")}`);
    }
    const items: SecretPromotionPreviewItem[] = [];
    for (const source of sources) {
      const target = targets.get(source.key);
      items.push({
        key: source.key,
        action: target === undefined ? "create" : "overwrite",
        changed: target === undefined ? true : await this.#valuesDiffer(transaction, source, target),
        sourceVersion: source.current_version,
        targetVersion: target?.current_version ?? null,
      });
    }
    return {
      sourceEnvironmentId,
      targetEnvironmentId,
      items,
      summary: {
        selected: items.length,
        created: items.filter(({ action }) => action === "create").length,
        overwritten: items.filter(({ action }) => action === "overwrite").length,
      },
    };
  }

  async #valuesDiffer(
    transaction: TenantTransaction,
    source: SecretValueRow,
    target: SecretValueRow,
  ): Promise<boolean> {
    const encryption = this.#encryption(transaction);
    const sourcePlaintext = await encryption.decrypt(this.#encrypted(source), {
      orgId: source.org_id,
      projectId: source.project_id,
      environmentId: source.environment_id,
      secretId: source.id,
      recordVersion: source.current_version,
    });
    let targetPlaintext: Buffer | undefined;
    try {
      targetPlaintext = await encryption.decrypt(this.#encrypted(target), {
        orgId: target.org_id,
        projectId: target.project_id,
        environmentId: target.environment_id,
        secretId: target.id,
        recordVersion: target.current_version,
      });
      return sourcePlaintext.length !== targetPlaintext.length
        || !timingSafeEqual(sourcePlaintext, targetPlaintext);
    } finally {
      sourcePlaintext.fill(0);
      targetPlaintext?.fill(0);
      encryption.clearKeyCache();
    }
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

  #versionContext(row: SecretVersionValueRow) {
    return {
      orgId: row.org_id,
      projectId: row.project_id,
      environmentId: row.environment_id,
      secretId: row.id,
      recordVersion: row.record_version,
    };
  }
}

const secretColumns = `s.id, s.org_id, s.project_id, s.environment_id, s.key,
  s.notes, s.current_version, s.created_at, s.updated_at,
  COALESCE((
    SELECT array_agg(st.tag_id ORDER BY lower(t.name), st.tag_id)
    FROM secret_tags st JOIN tags t ON t.id = st.tag_id AND t.org_id = st.org_id
    WHERE st.org_id = s.org_id AND st.secret_id = s.id
  ), '{}'::uuid[]) AS tag_ids,
  COALESCE((
    SELECT jsonb_agg(jsonb_build_object('id', t.id, 'name', t.name, 'color', t.color) ORDER BY lower(t.name), t.id)
    FROM secret_tags st JOIN tags t ON t.id = st.tag_id AND t.org_id = st.org_id
    WHERE st.org_id = s.org_id AND st.secret_id = s.id
  ), '[]'::jsonb) AS tags`;
const secretSelect = `SELECT ${secretColumns} FROM secrets s`;
