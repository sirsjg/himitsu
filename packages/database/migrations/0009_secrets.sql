BEGIN;

ALTER TABLE secrets ADD CONSTRAINT secrets_notes_length_check
  CHECK (notes IS NULL OR length(notes) <= 4000);

ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_ciphertext_size_check
  CHECK (octet_length(value_ciphertext) <= 65536);
ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_nonce_size_check
  CHECK (octet_length(nonce) = 12);
ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_auth_tag_size_check
  CHECK (octet_length(auth_tag) = 16);
ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_change_note_length_check
  CHECK (change_note IS NULL OR length(change_note) <= 1000);

COMMIT;
