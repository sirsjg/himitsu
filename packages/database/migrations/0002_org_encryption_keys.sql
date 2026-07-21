BEGIN;

CREATE TYPE data_key_status AS ENUM ('active', 'retired');

CREATE TABLE org_encryption_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  version integer NOT NULL CHECK (version > 0),
  status data_key_status NOT NULL,
  kek_id text NOT NULL CHECK (length(btrim(kek_id)) BETWEEN 1 AND 255),
  wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek) = 32),
  wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce) = 12),
  wrap_tag bytea NOT NULL CHECK (octet_length(wrap_tag) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  UNIQUE (org_id, version),
  CHECK (
    (status = 'active' AND retired_at IS NULL)
    OR (status = 'retired' AND retired_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX org_encryption_keys_one_active_idx
  ON org_encryption_keys (org_id)
  WHERE status = 'active';

COMMENT ON TABLE org_encryption_keys IS 'Per-organization DEKs wrapped by an external KEK; never stores plaintext key material.';
COMMENT ON COLUMN org_encryption_keys.wrapped_dek IS 'AES-256-GCM ciphertext of the 32-byte DEK.';

COMMIT;
