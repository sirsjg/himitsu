BEGIN;

CREATE TYPE organization_role AS ENUM ('owner', 'admin', 'member', 'read_only');
CREATE TYPE membership_status AS ENUM ('invited', 'active', 'suspended');
CREATE TYPE api_key_access AS ENUM ('read_only', 'read_write');
CREATE TYPE audit_actor_type AS ENUM ('user', 'api_key', 'system');

CREATE TABLE organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  audit_retention_days integer NOT NULL DEFAULT 90 CHECK (audit_retention_days >= 1),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL CHECK (length(btrim(email)) BETWEEN 3 AND 320),
  email_normalized text GENERATED ALWAYS AS (lower(btrim(email))) STORED UNIQUE,
  password_hash text,
  email_verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz
);

CREATE TABLE memberships (
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role organization_role NOT NULL,
  status membership_status NOT NULL DEFAULT 'active',
  invited_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

CREATE INDEX memberships_user_org_idx ON memberships (user_id, org_id);

CREATE TABLE projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  description text,
  settings jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object'),
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz,
  deleted_at timestamptz,
  UNIQUE (org_id, id),
  UNIQUE (org_id, slug)
);

CREATE INDEX projects_org_active_idx ON projects (org_id, created_at) WHERE deleted_at IS NULL;

CREATE TABLE environments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  project_id uuid NOT NULL,
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 80),
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  display_order integer NOT NULL DEFAULT 0,
  protected boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE,
  UNIQUE (org_id, project_id, id),
  UNIQUE (org_id, project_id, slug)
);

CREATE INDEX environments_org_project_order_idx
  ON environments (org_id, project_id, display_order, id)
  WHERE deleted_at IS NULL;

CREATE TABLE secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  project_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  key text NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
  notes text,
  current_version integer NOT NULL DEFAULT 0 CHECK (current_version >= 0),
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  FOREIGN KEY (org_id, project_id, environment_id)
    REFERENCES environments(org_id, project_id, id) ON DELETE CASCADE,
  UNIQUE (org_id, project_id, environment_id, id),
  CONSTRAINT secrets_org_project_environment_key_unique
    UNIQUE (org_id, project_id, environment_id, key)
);

CREATE INDEX secrets_org_project_environment_key_idx
  ON secrets (org_id, project_id, environment_id, key)
  WHERE deleted_at IS NULL;

CREATE TABLE secret_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  project_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  secret_id uuid NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  value_ciphertext bytea NOT NULL,
  nonce bytea NOT NULL,
  auth_tag bytea NOT NULL,
  encryption_key_version integer NOT NULL CHECK (encryption_key_version > 0),
  author_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  change_note text,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (org_id, project_id, environment_id, secret_id)
    REFERENCES secrets(org_id, project_id, environment_id, id) ON DELETE CASCADE,
  UNIQUE (org_id, secret_id, version)
);

CREATE INDEX secret_versions_org_secret_created_idx
  ON secret_versions (org_id, secret_id, created_at DESC);

CREATE TABLE tags (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 80),
  color text NOT NULL CHECK (color ~ '^#[0-9A-Fa-f]{6}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, id),
  UNIQUE (org_id, name)
);

CREATE TABLE secret_tags (
  org_id uuid NOT NULL,
  project_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  secret_id uuid NOT NULL,
  tag_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (org_id, project_id, environment_id, secret_id)
    REFERENCES secrets(org_id, project_id, environment_id, id) ON DELETE CASCADE,
  FOREIGN KEY (org_id, tag_id) REFERENCES tags(org_id, id) ON DELETE CASCADE,
  PRIMARY KEY (org_id, secret_id, tag_id)
);

CREATE INDEX secret_tags_org_tag_secret_idx ON secret_tags (org_id, tag_id, secret_id);

CREATE TABLE api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id uuid,
  environment_id uuid,
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
  prefix text NOT NULL CHECK (prefix ~ '^himi_[A-Za-z0-9]+$'),
  token_hash bytea NOT NULL UNIQUE,
  access api_key_access NOT NULL,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  CHECK (environment_id IS NULL OR project_id IS NOT NULL),
  CHECK (expires_at IS NULL OR expires_at > created_at),
  FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE,
  FOREIGN KEY (org_id, project_id, environment_id)
    REFERENCES environments(org_id, project_id, id) ON DELETE CASCADE,
  UNIQUE (org_id, id)
);

CREATE INDEX api_keys_org_scope_idx ON api_keys (org_id, project_id, environment_id);
CREATE INDEX api_keys_active_prefix_idx ON api_keys (prefix) WHERE revoked_at IS NULL;

CREATE TABLE audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  actor_type audit_actor_type NOT NULL,
  actor_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  actor_api_key_id uuid,
  action text NOT NULL CHECK (length(action) BETWEEN 1 AND 120),
  resource_type text NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 80),
  resource_id text,
  project_id uuid,
  environment_id uuid,
  ip inet,
  user_agent text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (actor_type = 'user' AND actor_user_id IS NOT NULL AND actor_api_key_id IS NULL)
    OR (actor_type = 'api_key' AND actor_api_key_id IS NOT NULL AND actor_user_id IS NULL)
    OR (actor_type = 'system' AND actor_user_id IS NULL AND actor_api_key_id IS NULL)
  ),
  FOREIGN KEY (org_id, actor_api_key_id) REFERENCES api_keys(org_id, id) ON DELETE RESTRICT
);

CREATE INDEX audit_events_org_occurred_idx ON audit_events (org_id, occurred_at DESC, id DESC);
CREATE INDEX audit_events_org_resource_idx ON audit_events (org_id, resource_type, resource_id);
CREATE INDEX audit_events_org_project_environment_idx
  ON audit_events (org_id, project_id, environment_id, occurred_at DESC);

COMMENT ON COLUMN secret_versions.value_ciphertext IS 'AES-256-GCM ciphertext only; plaintext must never be persisted.';
COMMENT ON COLUMN api_keys.token_hash IS 'One-way hash of the credential; the plaintext token is never persisted.';
COMMENT ON COLUMN audit_events.metadata IS 'Non-secret structured metadata; plaintext secret values are forbidden.';

COMMIT;
