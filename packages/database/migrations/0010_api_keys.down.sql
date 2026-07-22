BEGIN;
DROP FUNCTION IF EXISTS consume_api_key(text, bytea);
DROP INDEX IF EXISTS api_keys_prefix_unique_idx;
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_token_hash_length_check;
COMMIT;
