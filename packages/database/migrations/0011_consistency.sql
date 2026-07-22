BEGIN;

CREATE TABLE consistency_report_cache (
  org_id uuid NOT NULL,
  project_id uuid NOT NULL,
  source_fingerprint text NOT NULL CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
  findings jsonb NOT NULL CHECK (jsonb_typeof(findings) = 'array'),
  computed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, project_id),
  FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE
);

CREATE TABLE consistency_finding_states (
  org_id uuid NOT NULL,
  project_id uuid NOT NULL,
  finding_id text NOT NULL CHECK (finding_id ~ '^[0-9a-f]{64}$'),
  disposition text NOT NULL CHECK (disposition IN ('acknowledged', 'ignored')),
  note text CHECK (note IS NULL OR length(note) <= 1000),
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, project_id, finding_id),
  FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE
);

ALTER TABLE consistency_report_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE consistency_report_cache FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON consistency_report_cache
  USING (org_id = app_current_org_id())
  WITH CHECK (org_id = app_current_org_id());

ALTER TABLE consistency_finding_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE consistency_finding_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON consistency_finding_states
  USING (org_id = app_current_org_id())
  WITH CHECK (org_id = app_current_org_id());

COMMIT;
