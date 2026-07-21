import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import {
  CryptoError,
  EnvelopeEncryptionService,
  InMemoryDataKeyStore,
  LocalMasterKey,
  encryptedValuesEqual,
  type EncryptedSecretValue,
  type SecretEncryptionContext,
} from "../src/index.js";

function context(overrides: Partial<SecretEncryptionContext> = {}): SecretEncryptionContext {
  return {
    orgId: "org-alpha",
    projectId: "project-api",
    environmentId: "environment-production",
    secretId: "secret-database-url",
    recordVersion: 1,
    ...overrides,
  };
}

function service(store = new InMemoryDataKeyStore()): {
  store: InMemoryDataKeyStore;
  crypto: EnvelopeEncryptionService;
} {
  const wrapper = new LocalMasterKey("local-test-key-v1", randomBytes(32));
  return { store, crypto: new EnvelopeEncryptionService(store, wrapper) };
}

test("encrypts and decrypts with a per-organization wrapped DEK", async () => {
  const { crypto, store } = service();
  const plaintext = Buffer.from("postgresql://user:password@db/app", "utf8");
  const encrypted = await crypto.encrypt(plaintext, context());

  assert.equal(encrypted.algorithm, "aes-256-gcm");
  assert.equal(encrypted.keyVersion, 1);
  assert.equal(encrypted.nonce.byteLength, 12);
  assert.equal(encrypted.authTag.byteLength, 16);
  assert.notDeepEqual(encrypted.ciphertext, plaintext);
  assert.deepEqual(await crypto.decrypt(encrypted, context()), plaintext);

  const records = store.snapshot("org-alpha");
  assert.equal(records.length, 1);
  assert.equal(records[0]?.wrapped.ciphertext.byteLength, 32);
  assert.deepEqual(Object.keys(records[0]?.wrapped ?? {}).sort(), [
    "authTag",
    "ciphertext",
    "kekId",
    "nonce",
  ]);
  crypto.clearKeyCache();
});

test("uses a fresh nonce so equal plaintext produces different ciphertext", async () => {
  const { crypto } = service();
  const plaintext = Buffer.from("same-value");
  const first = await crypto.encrypt(plaintext, context({ recordVersion: 1 }));
  const second = await crypto.encrypt(plaintext, context({ recordVersion: 2 }));

  assert.equal(first.keyVersion, second.keyVersion);
  assert.equal(encryptedValuesEqual(first, second), false);
  assert.notDeepEqual(first.nonce, second.nonce);
});

test("binds ciphertext to organization and resource context", async () => {
  const { crypto } = service();
  const encrypted = await crypto.encrypt(Buffer.from("bound-value"), context());

  for (const changed of [
    context({ orgId: "org-beta" }),
    context({ projectId: "project-other" }),
    context({ environmentId: "environment-other" }),
    context({ secretId: "secret-other" }),
    context({ recordVersion: 2 }),
  ]) {
    await assert.rejects(
      crypto.decrypt(encrypted, changed),
      (error: unknown) => error instanceof CryptoError && error.code === "DECRYPTION_FAILED",
    );
  }
});

test("rejects tampering without returning sensitive details", async () => {
  const { crypto } = service();
  const encrypted = await crypto.encrypt(Buffer.from("do-not-disclose"), context());
  const tampered: EncryptedSecretValue = {
    ...encrypted,
    ciphertext: Buffer.from(encrypted.ciphertext),
  };
  tampered.ciphertext[0] = (tampered.ciphertext[0] ?? 0) ^ 1;

  await assert.rejects(crypto.decrypt(tampered, context()), (error: unknown) => {
    assert.ok(error instanceof CryptoError);
    assert.equal(error.code, "DECRYPTION_FAILED");
    assert.equal(error.message, "Unable to decrypt secret value");
    assert.equal(error.message.includes("do-not-disclose"), false);
    return true;
  });
});

test("rotates DEKs while retaining old versions for decryption", async () => {
  const { crypto, store } = service();
  const oldValue = await crypto.encrypt(Buffer.from("old"), context({ recordVersion: 1 }));
  assert.equal(await crypto.rotateDataKey("org-alpha"), 2);
  const newValue = await crypto.encrypt(Buffer.from("new"), context({ recordVersion: 2 }));

  assert.equal(oldValue.keyVersion, 1);
  assert.equal(newValue.keyVersion, 2);
  assert.equal((await crypto.decrypt(oldValue, context({ recordVersion: 1 }))).toString(), "old");
  assert.equal((await crypto.decrypt(newValue, context({ recordVersion: 2 }))).toString(), "new");
  assert.deepEqual(
    store.snapshot("org-alpha").map(({ version, status }) => ({ version, status })),
    [
      { version: 1, status: "retired" },
      { version: 2, status: "active" },
    ],
  );
});

test("serializes concurrent first use to one active DEK", async () => {
  const store = new InMemoryDataKeyStore();
  const { crypto } = service(store);
  const values = await Promise.all(
    Array.from({ length: 12 }, (_, index) =>
      crypto.encrypt(Buffer.from(`value-${index}`), context({ recordVersion: index + 1 })),
    ),
  );

  assert.deepEqual(new Set(values.map(({ keyVersion }) => keyVersion)), new Set([1]));
  assert.equal(store.snapshot("org-alpha").length, 1);
});

test("validates local master-key configuration and encryption context", async () => {
  assert.throws(
    () => new LocalMasterKey("bad", randomBytes(31)),
    (error: unknown) => error instanceof CryptoError && error.code === "INVALID_CONFIGURATION",
  );
  assert.throws(
    () => LocalMasterKey.fromBase64("bad", "not-base64"),
    (error: unknown) => error instanceof CryptoError && error.code === "INVALID_CONFIGURATION",
  );

  const { crypto } = service();
  await assert.rejects(
    crypto.encrypt(Buffer.from("value"), context({ orgId: "" })),
    (error: unknown) => error instanceof CryptoError && error.code === "INVALID_CONTEXT",
  );
});
