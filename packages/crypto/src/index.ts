import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import type { Pool, PoolClient, QueryResult, QueryResultRow } from "pg";

const ALGORITHM = "aes-256-gcm" as const;
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

export class CryptoError extends Error {
  readonly code: "INVALID_CONFIGURATION" | "DECRYPTION_FAILED" | "INVALID_CONTEXT";

  constructor(
    code: CryptoError["code"],
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "CryptoError";
    this.code = code;
  }
}

export interface WrappedDataKey {
  readonly kekId: string;
  readonly ciphertext: Buffer;
  readonly nonce: Buffer;
  readonly authTag: Buffer;
}

export interface KeyWrapper {
  readonly id: string;
  wrap(orgId: string, keyVersion: number, dataKey: Uint8Array): Promise<WrappedDataKey>;
  unwrap(orgId: string, keyVersion: number, wrapped: WrappedDataKey): Promise<Buffer>;
}

function dataKeyAad(orgId: string, keyVersion: number): Buffer {
  return Buffer.from(JSON.stringify(["himitsu-dek", 1, orgId, keyVersion]), "utf8");
}

export class LocalMasterKey implements KeyWrapper {
  readonly id: string;
  readonly #key: Buffer;

  constructor(id: string, key: Uint8Array) {
    if (!id.trim() || key.byteLength !== KEY_BYTES) {
      throw new CryptoError(
        "INVALID_CONFIGURATION",
        "The master key requires a non-empty id and exactly 32 bytes",
      );
    }
    this.id = id;
    this.#key = Buffer.from(key);
  }

  static fromBase64(id: string, encodedKey: string): LocalMasterKey {
    const key = Buffer.from(encodedKey, "base64");
    if (key.byteLength !== KEY_BYTES || key.toString("base64") !== encodedKey) {
      key.fill(0);
      throw new CryptoError(
        "INVALID_CONFIGURATION",
        "The base64 master key must decode canonically to exactly 32 bytes",
      );
    }
    try {
      return new LocalMasterKey(id, key);
    } finally {
      key.fill(0);
    }
  }

  async wrap(orgId: string, keyVersion: number, dataKey: Uint8Array): Promise<WrappedDataKey> {
    if (dataKey.byteLength !== KEY_BYTES) {
      throw new CryptoError("INVALID_CONFIGURATION", "A data key must contain exactly 32 bytes");
    }
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.#key, nonce, { authTagLength: TAG_BYTES });
    cipher.setAAD(dataKeyAad(orgId, keyVersion));
    const ciphertext = Buffer.concat([cipher.update(dataKey), cipher.final()]);
    return { kekId: this.id, ciphertext, nonce, authTag: cipher.getAuthTag() };
  }

  async unwrap(orgId: string, keyVersion: number, wrapped: WrappedDataKey): Promise<Buffer> {
    if (wrapped.kekId !== this.id) {
      throw new CryptoError("DECRYPTION_FAILED", "Unable to decrypt key material");
    }
    try {
      const decipher = createDecipheriv(ALGORITHM, this.#key, wrapped.nonce, {
        authTagLength: TAG_BYTES,
      });
      decipher.setAAD(dataKeyAad(orgId, keyVersion));
      decipher.setAuthTag(wrapped.authTag);
      const key = Buffer.concat([decipher.update(wrapped.ciphertext), decipher.final()]);
      if (key.byteLength !== KEY_BYTES) {
        key.fill(0);
        throw new Error("invalid unwrapped key length");
      }
      return key;
    } catch (error) {
      throw new CryptoError("DECRYPTION_FAILED", "Unable to decrypt key material", {
        cause: error,
      });
    }
  }
}

export interface DataKeyRecord {
  readonly orgId: string;
  readonly version: number;
  readonly status: "active" | "retired";
  readonly wrapped: WrappedDataKey;
  readonly createdAt: Date;
  readonly retiredAt: Date | null;
}

type WrappedKeyFactory = (version: number) => Promise<WrappedDataKey>;

export interface DataKeyStore {
  getActive(orgId: string): Promise<DataKeyRecord | null>;
  getVersion(orgId: string, version: number): Promise<DataKeyRecord | null>;
  ensureActive(orgId: string, factory: WrappedKeyFactory): Promise<DataKeyRecord>;
  rotate(orgId: string, factory: WrappedKeyFactory): Promise<DataKeyRecord>;
}

function cloneRecord(record: DataKeyRecord): DataKeyRecord {
  return {
    ...record,
    wrapped: {
      ...record.wrapped,
      ciphertext: Buffer.from(record.wrapped.ciphertext),
      nonce: Buffer.from(record.wrapped.nonce),
      authTag: Buffer.from(record.wrapped.authTag),
    },
    createdAt: new Date(record.createdAt),
    retiredAt: record.retiredAt === null ? null : new Date(record.retiredAt),
  };
}

export class InMemoryDataKeyStore implements DataKeyStore {
  readonly #records = new Map<string, DataKeyRecord[]>();
  readonly #locks = new Map<string, Promise<unknown>>();

  async #locked<T>(orgId: string, work: () => Promise<T>): Promise<T> {
    const previous = this.#locks.get(orgId) ?? Promise.resolve();
    const current = previous.then(work, work);
    this.#locks.set(orgId, current);
    try {
      return await current;
    } finally {
      if (this.#locks.get(orgId) === current) this.#locks.delete(orgId);
    }
  }

  async getActive(orgId: string): Promise<DataKeyRecord | null> {
    const record = this.#records.get(orgId)?.find(({ status }) => status === "active");
    return record === undefined ? null : cloneRecord(record);
  }

  async getVersion(orgId: string, version: number): Promise<DataKeyRecord | null> {
    const record = this.#records.get(orgId)?.find((candidate) => candidate.version === version);
    return record === undefined ? null : cloneRecord(record);
  }

  async ensureActive(orgId: string, factory: WrappedKeyFactory): Promise<DataKeyRecord> {
    return this.#locked(orgId, async () => {
      const existing = await this.getActive(orgId);
      return existing ?? this.#activate(orgId, factory);
    });
  }

  async rotate(orgId: string, factory: WrappedKeyFactory): Promise<DataKeyRecord> {
    return this.#locked(orgId, () => this.#activate(orgId, factory));
  }

  async #activate(orgId: string, factory: WrappedKeyFactory): Promise<DataKeyRecord> {
    const records = this.#records.get(orgId) ?? [];
    const version = Math.max(0, ...records.map((record) => record.version)) + 1;
    const now = new Date();
    for (const [index, record] of records.entries()) {
      if (record.status === "active") {
        records[index] = { ...record, status: "retired", retiredAt: now };
      }
    }
    const record: DataKeyRecord = {
      orgId,
      version,
      status: "active",
      wrapped: await factory(version),
      createdAt: now,
      retiredAt: null,
    };
    records.push(record);
    this.#records.set(orgId, records);
    return cloneRecord(record);
  }

  snapshot(orgId: string): readonly DataKeyRecord[] {
    return (this.#records.get(orgId) ?? []).map(cloneRecord);
  }
}

interface DataKeyRow {
  org_id: string;
  version: number;
  status: "active" | "retired";
  kek_id: string;
  wrapped_dek: Buffer;
  wrap_nonce: Buffer;
  wrap_tag: Buffer;
  created_at: Date;
  retired_at: Date | null;
}

function recordFromRow(row: DataKeyRow): DataKeyRecord {
  return {
    orgId: row.org_id,
    version: row.version,
    status: row.status,
    wrapped: {
      kekId: row.kek_id,
      ciphertext: row.wrapped_dek,
      nonce: row.wrap_nonce,
      authTag: row.wrap_tag,
    },
    createdAt: row.created_at,
    retiredAt: row.retired_at,
  };
}

export class PostgresDataKeyStore implements DataKeyStore {
  readonly #pool: Pool;

  constructor(pool: Pool) {
    this.#pool = pool;
  }

  async getActive(orgId: string): Promise<DataKeyRecord | null> {
    const result = await this.#pool.query<DataKeyRow>(
      `SELECT org_id, version, status, kek_id, wrapped_dek, wrap_nonce, wrap_tag, created_at, retired_at
       FROM org_encryption_keys WHERE org_id = $1 AND status = 'active'`,
      [orgId],
    );
    const row = result.rows[0];
    return row === undefined ? null : recordFromRow(row);
  }

  async getVersion(orgId: string, version: number): Promise<DataKeyRecord | null> {
    const result = await this.#pool.query<DataKeyRow>(
      `SELECT org_id, version, status, kek_id, wrapped_dek, wrap_nonce, wrap_tag, created_at, retired_at
       FROM org_encryption_keys WHERE org_id = $1 AND version = $2`,
      [orgId, version],
    );
    const row = result.rows[0];
    return row === undefined ? null : recordFromRow(row);
  }

  async ensureActive(orgId: string, factory: WrappedKeyFactory): Promise<DataKeyRecord> {
    return this.#activate(orgId, factory, true);
  }

  async rotate(orgId: string, factory: WrappedKeyFactory): Promise<DataKeyRecord> {
    return this.#activate(orgId, factory, false);
  }

  async #activate(
    orgId: string,
    factory: WrappedKeyFactory,
    useExisting: boolean,
  ): Promise<DataKeyRecord> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [orgId]);
      if (useExisting) {
        const existing = await this.#selectActive(client, orgId);
        if (existing !== null) {
          await client.query("COMMIT");
          return existing;
        }
      }
      const versionResult = await client.query<{ version: number }>(
        "SELECT COALESCE(max(version), 0)::integer + 1 AS version FROM org_encryption_keys WHERE org_id = $1",
        [orgId],
      );
      const version = versionResult.rows[0]?.version;
      if (version === undefined) throw new Error("Unable to allocate a data-key version");
      const wrapped = await factory(version);
      await client.query(
        "UPDATE org_encryption_keys SET status = 'retired', retired_at = now() WHERE org_id = $1 AND status = 'active'",
        [orgId],
      );
      const inserted = await client.query<DataKeyRow>(
        `INSERT INTO org_encryption_keys
          (org_id, version, status, kek_id, wrapped_dek, wrap_nonce, wrap_tag)
         VALUES ($1, $2, 'active', $3, $4, $5, $6)
         RETURNING org_id, version, status, kek_id, wrapped_dek, wrap_nonce, wrap_tag, created_at, retired_at`,
        [orgId, version, wrapped.kekId, wrapped.ciphertext, wrapped.nonce, wrapped.authTag],
      );
      const row = inserted.rows[0];
      if (row === undefined) throw new Error("Data-key insertion returned no record");
      await client.query("COMMIT");
      return recordFromRow(row);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async #selectActive(client: PoolClient, orgId: string): Promise<DataKeyRecord | null> {
    const result = await client.query<DataKeyRow>(
      `SELECT org_id, version, status, kek_id, wrapped_dek, wrap_nonce, wrap_tag, created_at, retired_at
       FROM org_encryption_keys WHERE org_id = $1 AND status = 'active'`,
      [orgId],
    );
    const row = result.rows[0];
    return row === undefined ? null : recordFromRow(row);
  }
}

export interface DataKeyTransaction {
  query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<QueryResult<Row>>;
}

/**
 * A data-key store bound to an existing database transaction. This is the
 * adapter used by tenant-scoped writes so key activation and encrypted data
 * commit or roll back together under the caller's RLS context.
 */
export class PostgresTransactionDataKeyStore implements DataKeyStore {
  readonly #transaction: DataKeyTransaction;

  constructor(transaction: DataKeyTransaction) {
    this.#transaction = transaction;
  }

  async getActive(orgId: string): Promise<DataKeyRecord | null> {
    return this.#selectActive(orgId);
  }

  async getVersion(orgId: string, version: number): Promise<DataKeyRecord | null> {
    const result = await this.#transaction.query<DataKeyRow>(
      `SELECT org_id, version, status, kek_id, wrapped_dek, wrap_nonce, wrap_tag, created_at, retired_at
       FROM org_encryption_keys WHERE org_id = $1 AND version = $2`,
      [orgId, version],
    );
    const row = result.rows[0];
    return row === undefined ? null : recordFromRow(row);
  }

  async ensureActive(orgId: string, factory: WrappedKeyFactory): Promise<DataKeyRecord> {
    return this.#activate(orgId, factory, true);
  }

  async rotate(orgId: string, factory: WrappedKeyFactory): Promise<DataKeyRecord> {
    return this.#activate(orgId, factory, false);
  }

  async #activate(
    orgId: string,
    factory: WrappedKeyFactory,
    useExisting: boolean,
  ): Promise<DataKeyRecord> {
    await this.#transaction.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [orgId]);
    if (useExisting) {
      const existing = await this.#selectActive(orgId);
      if (existing !== null) return existing;
    }
    const versionResult = await this.#transaction.query<{ version: number }>(
      "SELECT COALESCE(max(version), 0)::integer + 1 AS version FROM org_encryption_keys WHERE org_id = $1",
      [orgId],
    );
    const version = versionResult.rows[0]?.version;
    if (version === undefined) throw new Error("Unable to allocate a data-key version");
    const wrapped = await factory(version);
    await this.#transaction.query(
      "UPDATE org_encryption_keys SET status = 'retired', retired_at = now() WHERE org_id = $1 AND status = 'active'",
      [orgId],
    );
    const inserted = await this.#transaction.query<DataKeyRow>(
      `INSERT INTO org_encryption_keys
        (org_id, version, status, kek_id, wrapped_dek, wrap_nonce, wrap_tag)
       VALUES ($1, $2, 'active', $3, $4, $5, $6)
       RETURNING org_id, version, status, kek_id, wrapped_dek, wrap_nonce, wrap_tag, created_at, retired_at`,
      [orgId, version, wrapped.kekId, wrapped.ciphertext, wrapped.nonce, wrapped.authTag],
    );
    const row = inserted.rows[0];
    if (row === undefined) throw new Error("Data-key insertion returned no record");
    return recordFromRow(row);
  }

  async #selectActive(orgId: string): Promise<DataKeyRecord | null> {
    const result = await this.#transaction.query<DataKeyRow>(
      `SELECT org_id, version, status, kek_id, wrapped_dek, wrap_nonce, wrap_tag, created_at, retired_at
       FROM org_encryption_keys WHERE org_id = $1 AND status = 'active'`,
      [orgId],
    );
    const row = result.rows[0];
    return row === undefined ? null : recordFromRow(row);
  }
}

export interface SecretEncryptionContext {
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly secretId: string;
  readonly recordVersion: number;
}

export interface EncryptedSecretValue {
  readonly algorithm: typeof ALGORITHM;
  readonly keyVersion: number;
  readonly ciphertext: Buffer;
  readonly nonce: Buffer;
  readonly authTag: Buffer;
}

function secretAad(context: SecretEncryptionContext): Buffer {
  if (
    !context.orgId ||
    !context.projectId ||
    !context.environmentId ||
    !context.secretId ||
    !Number.isSafeInteger(context.recordVersion) ||
    context.recordVersion < 1
  ) {
    throw new CryptoError("INVALID_CONTEXT", "Encryption context is incomplete or invalid");
  }
  return Buffer.from(
    JSON.stringify([
      "himitsu-secret",
      1,
      context.orgId,
      context.projectId,
      context.environmentId,
      context.secretId,
      context.recordVersion,
    ]),
    "utf8",
  );
}

interface CacheEntry {
  readonly key: Buffer;
  readonly expiresAt: number;
}

export class EnvelopeEncryptionService {
  readonly #store: DataKeyStore;
  readonly #wrapper: KeyWrapper;
  readonly #cache = new Map<string, CacheEntry>();
  readonly #cacheTtlMs: number;
  readonly #maxCacheEntries: number;
  readonly #now: () => number;

  constructor(
    store: DataKeyStore,
    wrapper: KeyWrapper,
    options: { cacheTtlMs?: number; maxCacheEntries?: number; now?: () => number } = {},
  ) {
    this.#store = store;
    this.#wrapper = wrapper;
    this.#cacheTtlMs = options.cacheTtlMs ?? 60_000;
    this.#maxCacheEntries = options.maxCacheEntries ?? 256;
    this.#now = options.now ?? Date.now;
    if (
      this.#cacheTtlMs < 0 ||
      !Number.isSafeInteger(this.#maxCacheEntries) ||
      this.#maxCacheEntries < 1
    ) {
      throw new CryptoError("INVALID_CONFIGURATION", "The key-cache limits are invalid");
    }
  }

  async encrypt(
    plaintext: Uint8Array,
    context: SecretEncryptionContext,
  ): Promise<EncryptedSecretValue> {
    secretAad(context);
    const record = await this.#store.ensureActive(context.orgId, (version) =>
      this.#generateWrappedKey(context.orgId, version),
    );
    const key = await this.#loadKey(record);
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv(ALGORITHM, key, nonce, { authTagLength: TAG_BYTES });
    cipher.setAAD(secretAad(context));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      algorithm: ALGORITHM,
      keyVersion: record.version,
      ciphertext,
      nonce,
      authTag: cipher.getAuthTag(),
    };
  }

  async decrypt(
    encrypted: EncryptedSecretValue,
    context: SecretEncryptionContext,
  ): Promise<Buffer> {
    try {
      if (
        encrypted.algorithm !== ALGORITHM ||
        encrypted.nonce.byteLength !== NONCE_BYTES ||
        encrypted.authTag.byteLength !== TAG_BYTES
      ) {
        throw new Error("invalid encrypted value metadata");
      }
      const record = await this.#store.getVersion(context.orgId, encrypted.keyVersion);
      if (record === null) throw new Error("unknown data-key version");
      const key = await this.#loadKey(record);
      const decipher = createDecipheriv(ALGORITHM, key, encrypted.nonce, {
        authTagLength: TAG_BYTES,
      });
      decipher.setAAD(secretAad(context));
      decipher.setAuthTag(encrypted.authTag);
      return Buffer.concat([decipher.update(encrypted.ciphertext), decipher.final()]);
    } catch (error) {
      if (error instanceof CryptoError && error.code === "INVALID_CONTEXT") throw error;
      throw new CryptoError("DECRYPTION_FAILED", "Unable to decrypt secret value", {
        cause: error,
      });
    }
  }

  async rotateDataKey(orgId: string): Promise<number> {
    if (!orgId) throw new CryptoError("INVALID_CONTEXT", "Organization id is required");
    const record = await this.#store.rotate(orgId, (version) =>
      this.#generateWrappedKey(orgId, version),
    );
    return record.version;
  }

  clearKeyCache(): void {
    for (const entry of this.#cache.values()) entry.key.fill(0);
    this.#cache.clear();
  }

  async #generateWrappedKey(orgId: string, version: number): Promise<WrappedDataKey> {
    const key = randomBytes(KEY_BYTES);
    try {
      return await this.#wrapper.wrap(orgId, version, key);
    } finally {
      key.fill(0);
    }
  }

  async #loadKey(record: DataKeyRecord): Promise<Buffer> {
    const cacheKey = `${record.orgId}:${record.version}`;
    const cached = this.#cache.get(cacheKey);
    const now = this.#now();
    if (cached !== undefined) {
      if (cached.expiresAt > now) return cached.key;
      cached.key.fill(0);
      this.#cache.delete(cacheKey);
    }
    const key = await this.#wrapper.unwrap(record.orgId, record.version, record.wrapped);
    if (this.#cache.size >= this.#maxCacheEntries) {
      const oldestCacheKey = this.#cache.keys().next().value as string | undefined;
      if (oldestCacheKey !== undefined) {
        this.#cache.get(oldestCacheKey)?.key.fill(0);
        this.#cache.delete(oldestCacheKey);
      }
    }
    this.#cache.set(cacheKey, { key, expiresAt: now + this.#cacheTtlMs });
    return key;
  }
}

export function encryptedValuesEqual(
  left: EncryptedSecretValue,
  right: EncryptedSecretValue,
): boolean {
  return (
    left.algorithm === right.algorithm &&
    left.keyVersion === right.keyVersion &&
    left.ciphertext.byteLength === right.ciphertext.byteLength &&
    left.nonce.byteLength === right.nonce.byteLength &&
    left.authTag.byteLength === right.authTag.byteLength &&
    timingSafeEqual(left.ciphertext, right.ciphertext) &&
    timingSafeEqual(left.nonce, right.nonce) &&
    timingSafeEqual(left.authTag, right.authTag)
  );
}
