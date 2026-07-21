BEGIN;

CREATE TABLE project_role_overrides (
  org_id uuid NOT NULL,
  project_id uuid NOT NULL,
  user_id uuid NOT NULL,
  role organization_role NOT NULL CHECK (role <> 'owner'),
  created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE,
  FOREIGN KEY (org_id, user_id) REFERENCES memberships(org_id, user_id) ON DELETE CASCADE,
  PRIMARY KEY (org_id, project_id, user_id)
);

CREATE INDEX project_role_overrides_user_project_idx
  ON project_role_overrides (org_id, user_id, project_id);

ALTER TABLE project_role_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_role_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON project_role_overrides
  USING (org_id = app_current_org_id())
  WITH CHECK (org_id = app_current_org_id());

COMMIT;
