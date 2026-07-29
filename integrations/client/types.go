package client

import "time"

// Tag is a colour-coded label attached to projects and secrets.
type Tag struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Color     string    `json:"color"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

// ProjectSettings carries the per-project defaults applied to new environments.
type ProjectSettings struct {
	DefaultEnvironments []string `json:"defaultEnvironments"`
}

// Project is a Himitsu project: the unit that owns environments and secrets.
type Project struct {
	ID          string          `json:"id"`
	OrgID       string          `json:"orgId"`
	Name        string          `json:"name"`
	Slug        string          `json:"slug"`
	Description *string         `json:"description"`
	Settings    ProjectSettings `json:"settings"`
	TagIDs      []string        `json:"tagIds"`
	Tags        []Tag           `json:"tags"`
	ArchivedAt  *time.Time      `json:"archivedAt"`
	DeletedAt   *time.Time      `json:"deletedAt"`
	PurgeAfter  *time.Time      `json:"purgeAfter"`
}

// CreateProjectInput is the body of POST /api/v1/projects.
type CreateProjectInput struct {
	Name                string   `json:"name"`
	Slug                string   `json:"slug"`
	Description         *string  `json:"description,omitempty"`
	DefaultEnvironments []string `json:"defaultEnvironments,omitempty"`
	TagIDs              []string `json:"tagIds,omitempty"`
}

// UpdateProjectInput is the body of PATCH /api/v1/projects/{id}. Every field is
// optional; nil means "leave unchanged".
type UpdateProjectInput struct {
	Name                *string  `json:"name,omitempty"`
	Slug                *string  `json:"slug,omitempty"`
	Description         *string  `json:"description,omitempty"`
	DefaultEnvironments []string `json:"defaultEnvironments,omitempty"`
	TagIDs              []string `json:"tagIds,omitempty"`
}

// Environment is a deployment target within a project.
type Environment struct {
	ID           string     `json:"id"`
	OrgID        string     `json:"orgId"`
	ProjectID    string     `json:"projectId"`
	Name         string     `json:"name"`
	Slug         string     `json:"slug"`
	DisplayOrder int        `json:"displayOrder"`
	Protected    bool       `json:"protected"`
	DeletedAt    *time.Time `json:"deletedAt"`
	PurgeAfter   *time.Time `json:"purgeAfter"`
}

// CreateEnvironmentInput is the body of POST .../environments.
type CreateEnvironmentInput struct {
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Protected *bool  `json:"protected,omitempty"`
}

// UpdateEnvironmentInput is the body of PATCH .../environments/{id}.
type UpdateEnvironmentInput struct {
	Name      *string `json:"name,omitempty"`
	Slug      *string `json:"slug,omitempty"`
	Protected *bool   `json:"protected,omitempty"`
}

// Secret is secret metadata. The plaintext value is never present here; use
// GetSecret, which hits the value-returning endpoint and records an audit read.
type Secret struct {
	ID             string    `json:"id"`
	OrgID          string    `json:"orgId"`
	ProjectID      string    `json:"projectId"`
	EnvironmentID  string    `json:"environmentId"`
	Key            string    `json:"key"`
	Notes          *string   `json:"notes"`
	CurrentVersion int       `json:"currentVersion"`
	TagIDs         []string  `json:"tagIds"`
	Tags           []Tag     `json:"tags"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// SecretWithValue is a secret including decrypted plaintext.
type SecretWithValue struct {
	Secret
	Value string `json:"value"`
}

// CreateSecretInput is the body of POST .../secrets.
type CreateSecretInput struct {
	Key                   string   `json:"key"`
	Value                 string   `json:"value"`
	Notes                 *string  `json:"notes,omitempty"`
	ChangeNote            *string  `json:"changeNote,omitempty"`
	AllowNonConformingKey *bool    `json:"allowNonConformingKey,omitempty"`
	TagIDs                []string `json:"tagIds,omitempty"`
}

// UpdateSecretInput is the body of PATCH /api/v1/secrets/{id}. Value is
// required by the API even when only metadata changes.
type UpdateSecretInput struct {
	Value      string   `json:"value"`
	Notes      *string  `json:"notes,omitempty"`
	ChangeNote *string  `json:"changeNote,omitempty"`
	TagIDs     []string `json:"tagIds,omitempty"`
}

// APIKeyAccess is the coarse capability grant on a token.
type APIKeyAccess string

const (
	AccessReadOnly  APIKeyAccess = "read_only"
	AccessReadWrite APIKeyAccess = "read_write"
)

// APIKey is a service token's metadata. The token itself is returned exactly
// once, by CreateAPIKey.
type APIKey struct {
	ID            string       `json:"id"`
	OrgID         string       `json:"orgId"`
	ProjectID     *string      `json:"projectId"`
	EnvironmentID *string      `json:"environmentId"`
	Name          string       `json:"name"`
	Prefix        string       `json:"prefix"`
	Access        APIKeyAccess `json:"access"`
	CreatedAt     time.Time    `json:"createdAt"`
	ExpiresAt     *time.Time   `json:"expiresAt"`
	LastUsedAt    *time.Time   `json:"lastUsedAt"`
	RevokedAt     *time.Time   `json:"revokedAt"`
}

// CreateAPIKeyInput is the body of POST /api/v1/api-keys.
type CreateAPIKeyInput struct {
	Name          string       `json:"name"`
	Access        APIKeyAccess `json:"access"`
	ProjectID     *string      `json:"projectId,omitempty"`
	EnvironmentID *string      `json:"environmentId,omitempty"`
	ExpiresAt     *time.Time   `json:"expiresAt,omitempty"`
}

// CreatedAPIKey pairs the new key with its one-time plaintext token.
type CreatedAPIKey struct {
	APIKey APIKey `json:"apiKey"`
	Token  string `json:"token"`
}

// CreateTagInput is the body of POST /api/v1/tags.
type CreateTagInput struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

// UpdateTagInput is the body of PATCH /api/v1/tags/{id}.
type UpdateTagInput struct {
	Name  *string `json:"name,omitempty"`
	Color *string `json:"color,omitempty"`
}

// ExportFormat selects the serialisation of an environment export.
type ExportFormat string

const (
	FormatDotenv ExportFormat = "dotenv"
	FormatJSON   ExportFormat = "json"
	FormatShell  ExportFormat = "shell"
)

// Export is a rendered environment export.
type Export struct {
	Format      ExportFormat `json:"format"`
	Filename    string       `json:"filename"`
	MimeType    string       `json:"mimeType"`
	Content     string       `json:"content"`
	SecretCount int          `json:"secretCount"`
	Nested      bool         `json:"nested"`
}

// RuntimeConfig is the response of the runtime endpoint.
//
// NotModified is true when the server answered 304 because the caller's known
// config version was still current; Secrets is then nil and must not be treated
// as an empty environment.
type RuntimeConfig struct {
	ConfigVersion int64             `json:"configVersion"`
	Secrets       map[string]string `json:"secrets"`
	NotModified   bool              `json:"-"`
}

// Ptr returns a pointer to v. It shortens building the optional fields above.
func Ptr[T any](v T) *T { return &v }
