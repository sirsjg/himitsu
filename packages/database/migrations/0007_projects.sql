BEGIN;

ALTER TABLE projects ADD COLUMN purge_after timestamptz;
ALTER TABLE projects ADD CONSTRAINT projects_deletion_window_check CHECK (
  (deleted_at IS NULL AND purge_after IS NULL)
  OR (deleted_at IS NOT NULL AND purge_after > deleted_at)
);

ALTER TABLE environments ADD COLUMN deleted_by_project_at timestamptz;
ALTER TABLE environments ADD CONSTRAINT environments_project_deletion_check
  CHECK (deleted_by_project_at IS NULL OR deleted_at IS NOT NULL);

ALTER TABLE secrets ADD COLUMN deleted_by_project_at timestamptz;
ALTER TABLE secrets ADD CONSTRAINT secrets_project_deletion_check
  CHECK (deleted_by_project_at IS NULL OR deleted_at IS NOT NULL);

CREATE TABLE project_tags (
  org_id uuid NOT NULL,
  project_id uuid NOT NULL,
  tag_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE,
  FOREIGN KEY (org_id, tag_id) REFERENCES tags(org_id, id) ON DELETE CASCADE,
  PRIMARY KEY (org_id, project_id, tag_id)
);

CREATE INDEX project_tags_org_tag_project_idx ON project_tags (org_id, tag_id, project_id);

ALTER TABLE project_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_tags FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON project_tags
  USING (org_id = app_current_org_id())
  WITH CHECK (org_id = app_current_org_id());

COMMIT;
