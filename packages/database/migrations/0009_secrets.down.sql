BEGIN;
ALTER TABLE secret_versions DROP CONSTRAINT IF EXISTS secret_versions_change_note_length_check;
ALTER TABLE secret_versions DROP CONSTRAINT IF EXISTS secret_versions_auth_tag_size_check;
ALTER TABLE secret_versions DROP CONSTRAINT IF EXISTS secret_versions_nonce_size_check;
ALTER TABLE secret_versions DROP CONSTRAINT IF EXISTS secret_versions_ciphertext_size_check;
ALTER TABLE secrets DROP CONSTRAINT IF EXISTS secrets_notes_length_check;
COMMIT;
