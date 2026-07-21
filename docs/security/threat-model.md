# Encryption threat model

## Scope and assets

This model covers secret values and organization data-encryption keys (DEKs) from receipt by the API through encryption, PostgreSQL storage, decryption, rotation, logging, and backup. The protected assets are secret plaintext, unwrapped DEKs, and the key-encryption key (KEK). Availability, endpoint authorization, and host hardening are related controls but do not replace encryption.

## Trust boundaries and assumptions

- TLS protects traffic before it reaches the API process.
- The API host is trusted while processing an authorized request. A fully compromised API process can observe plaintext that it is asked to decrypt; envelope encryption does not prevent this.
- PostgreSQL, its replicas, snapshots, and backups are not trusted with plaintext or an unwrapped DEK.
- The production KEK lives in a KMS/HSM and is usable only by the API workload identity. Self-hosted installations provide an exactly 32-byte base64 master key through a mounted runtime secret, separate from the database and backups.
- Operating-system entropy is trusted for Node.js `randomBytes`.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Database or backup theft | Secret values use AES-256-GCM under per-organization DEKs; only wrapped DEKs are stored. The KEK is held separately. | An attacker who also obtains KEK access can unwrap DEKs. |
| Cross-tenant ciphertext substitution | AES-GCM authenticated data binds organization, project, environment, secret id, and record version. DEK wrapping binds organization and key version. | An authorized API compromise can request legitimate decryptions. |
| Ciphertext, nonce, or tag modification | GCM authentication fails closed with a generic error that contains no plaintext or supplied value. | Destructive tampering can still cause loss of availability. |
| GCM nonce reuse | Every encryption and key wrap obtains a fresh 96-bit nonce from the OS CSPRNG. Tests assert repeated plaintext does not reuse nonce/ciphertext. | The negligible random-collision probability remains. |
| One tenant key exposing all tenants | Each organization receives an independent random 256-bit DEK with serialized creation and one active version. | Compromise of the KEK can expose every wrapped DEK accessible to it. |
| Key material written to durable storage | The key store accepts only wrapped-key fields; raw DEKs are zeroed after wrapping and cached only in bounded-lifetime process memory. Logs have no crypto inputs. | Node.js cannot guarantee compiler/runtime memory zeroization or prevent copies inside native crypto. |
| Secret leakage in errors or logs | Crypto errors are stable generic codes/messages. The package has no logger and never formats plaintext, ciphertext, credentials, or key material. | Callers must maintain the repository-wide redaction policy. |
| Concurrent rotation races | PostgreSQL advisory transaction locks serialize key creation and rotation per organization; a partial change rolls back. A partial unique index permits one active DEK. | A long-running transaction can delay rotation for that organization. |

## DEK rotation strategy

1. Acquire the organization-scoped transaction lock.
2. Generate a new 256-bit DEK in memory, wrap it with the configured KEK, and insert the next monotonically increasing version as active while retiring the previous version in the same transaction.
3. New secret writes immediately use the active version. Reads select the DEK version recorded with each ciphertext, so old values remain decryptable.
4. Re-encrypt old secret versions in resumable, idempotent batches. Each successful replacement is authenticated against the same resource context and records the new DEK version.
5. Verify that no ciphertext references the retired version before deleting its wrapped record. Retain it if policy requires historical versions to stay decryptable.

KEK rotation is separate: configure a key wrapper capable of reading the old KEK id, unwrap each DEK, and re-wrap it under the new KEK without decrypting secret values. Keep the old KEK available until every wrapped record is verified. Rotation events record organization, version, KEK id, outcome, and actor but never key material.

## Out of scope and follow-up

- Browser and API authorization are enforced by the authn/RBAC layers.
- Host compromise, crash dumps, swap, and process inspection require deployment hardening and short key-cache lifetimes.
- Audit-event integrity, secret-access auditing, backup encryption, and recovery drills are delivered by their dedicated project issues.
