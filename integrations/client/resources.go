package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// pageSize is the per-request limit used when walking paginated collections.
const pageSize = 100

func requireID(label, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("himitsu: %s is required", label)
	}
	return nil
}

// listAll walks a paginated collection until it has every item. The API caps
// page size server-side, so a single unbounded request is not an option.
func listAll[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	if query == nil {
		query = url.Values{}
	}
	var all []T
	for offset := 0; ; {
		page := url.Values{}
		for key, values := range query {
			page[key] = values
		}
		page.Set("limit", strconv.Itoa(pageSize))
		page.Set("offset", strconv.Itoa(offset))

		var items []T
		var meta envelope
		if _, err := c.do(ctx, request{
			method: http.MethodGet,
			path:   path,
			query:  page,
			out:    &items,
			meta:   &meta,
		}); err != nil {
			return nil, err
		}

		all = append(all, items...)
		// Stop on a short page as well as on reaching the reported total, so a
		// missing or stale meta.total cannot spin this loop forever.
		if len(items) == 0 || len(items) < pageSize || len(all) >= meta.Meta.Total {
			return all, nil
		}
		offset += len(items)
	}
}

// ---- Projects ----

// ListProjects returns every project visible to the token.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	return listAll[Project](ctx, c, "/api/v1/projects", nil)
}

// GetProject fetches one project by id.
func (c *Client) GetProject(ctx context.Context, projectID string) (*Project, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	var project Project
	_, err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/api/v1/projects/" + url.PathEscape(projectID),
		out:    &project,
	})
	if err != nil {
		return nil, err
	}
	return &project, nil
}

// CreateProject creates a project. When DefaultEnvironments is set the API also
// creates those environments, which Terraform users should be aware of: those
// environments are not tracked by the himitsu_project resource.
func (c *Client) CreateProject(ctx context.Context, input CreateProjectInput) (*Project, error) {
	var project Project
	_, err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/projects",
		body:   input,
		out:    &project,
	})
	if err != nil {
		return nil, err
	}
	return &project, nil
}

// UpdateProject applies a partial update.
func (c *Client) UpdateProject(ctx context.Context, projectID string, input UpdateProjectInput) (*Project, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	var project Project
	_, err := c.do(ctx, request{
		method: http.MethodPatch,
		path:   "/api/v1/projects/" + url.PathEscape(projectID),
		body:   input,
		out:    &project,
	})
	if err != nil {
		return nil, err
	}
	return &project, nil
}

// DeleteProject soft-deletes a project.
func (c *Client) DeleteProject(ctx context.Context, projectID string) error {
	if err := requireID("project id", projectID); err != nil {
		return err
	}
	_, err := c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/api/v1/projects/" + url.PathEscape(projectID),
	})
	return err
}

// ---- Environments ----

// ListEnvironments returns every environment in a project.
func (c *Client) ListEnvironments(ctx context.Context, projectID string) ([]Environment, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	return listAll[Environment](ctx, c, "/api/v1/projects/"+url.PathEscape(projectID)+"/environments", nil)
}

// GetEnvironment fetches one environment.
func (c *Client) GetEnvironment(ctx context.Context, projectID, environmentID string) (*Environment, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	if err := requireID("environment id", environmentID); err != nil {
		return nil, err
	}
	var environment Environment
	_, err := c.do(ctx, request{
		method: http.MethodGet,
		path: fmt.Sprintf("/api/v1/projects/%s/environments/%s",
			url.PathEscape(projectID), url.PathEscape(environmentID)),
		out: &environment,
	})
	if err != nil {
		return nil, err
	}
	return &environment, nil
}

// CreateEnvironment creates an environment in a project.
func (c *Client) CreateEnvironment(ctx context.Context, projectID string, input CreateEnvironmentInput) (*Environment, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	var environment Environment
	_, err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/projects/" + url.PathEscape(projectID) + "/environments",
		body:   input,
		out:    &environment,
	})
	if err != nil {
		return nil, err
	}
	return &environment, nil
}

// UpdateEnvironment applies a partial update.
func (c *Client) UpdateEnvironment(ctx context.Context, projectID, environmentID string, input UpdateEnvironmentInput) (*Environment, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	if err := requireID("environment id", environmentID); err != nil {
		return nil, err
	}
	var environment Environment
	_, err := c.do(ctx, request{
		method: http.MethodPatch,
		path: fmt.Sprintf("/api/v1/projects/%s/environments/%s",
			url.PathEscape(projectID), url.PathEscape(environmentID)),
		body: input,
		out:  &environment,
	})
	if err != nil {
		return nil, err
	}
	return &environment, nil
}

// DeleteEnvironment removes an environment. The API refuses to delete an
// environment that still holds secrets unless confirmSecrets is true, which
// makes accidental destruction of a populated environment a deliberate act.
func (c *Client) DeleteEnvironment(ctx context.Context, projectID, environmentID string, confirmSecrets bool) error {
	if err := requireID("project id", projectID); err != nil {
		return err
	}
	if err := requireID("environment id", environmentID); err != nil {
		return err
	}
	query := url.Values{}
	if confirmSecrets {
		query.Set("confirmSecrets", "true")
	}
	_, err := c.do(ctx, request{
		method: http.MethodDelete,
		path: fmt.Sprintf("/api/v1/projects/%s/environments/%s",
			url.PathEscape(projectID), url.PathEscape(environmentID)),
		query: query,
	})
	return err
}

// ---- Secrets ----

// ListSecrets returns metadata for every secret in an environment. Values are
// not included; each would require its own audited read.
func (c *Client) ListSecrets(ctx context.Context, projectID, environmentID string) ([]Secret, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	if err := requireID("environment id", environmentID); err != nil {
		return nil, err
	}
	return listAll[Secret](ctx, c, fmt.Sprintf("/api/v1/projects/%s/environments/%s/secrets",
		url.PathEscape(projectID), url.PathEscape(environmentID)), nil)
}

// GetSecret fetches one secret including its decrypted value. This records a
// secret.read audit event server-side.
func (c *Client) GetSecret(ctx context.Context, secretID string) (*SecretWithValue, error) {
	if err := requireID("secret id", secretID); err != nil {
		return nil, err
	}
	var secret SecretWithValue
	_, err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/api/v1/secrets/" + url.PathEscape(secretID),
		out:    &secret,
	})
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// FindSecretByKey locates a secret by key within an environment. The API has no
// lookup-by-key endpoint, so this filters the metadata listing. It returns a
// 404-shaped error when absent, letting callers use IsNotFound uniformly.
func (c *Client) FindSecretByKey(ctx context.Context, projectID, environmentID, key string) (*Secret, error) {
	if err := requireID("secret key", key); err != nil {
		return nil, err
	}
	secrets, err := c.ListSecrets(ctx, projectID, environmentID)
	if err != nil {
		return nil, err
	}
	for i := range secrets {
		if secrets[i].Key == key {
			return &secrets[i], nil
		}
	}
	return nil, &Error{
		StatusCode: http.StatusNotFound,
		Code:       "NOT_FOUND",
		Message:    fmt.Sprintf("secret %q not found in environment %s", key, environmentID),
	}
}

// CreateSecret adds a secret to an environment.
func (c *Client) CreateSecret(ctx context.Context, projectID, environmentID string, input CreateSecretInput) (*Secret, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	if err := requireID("environment id", environmentID); err != nil {
		return nil, err
	}
	var secret Secret
	_, err := c.do(ctx, request{
		method: http.MethodPost,
		path: fmt.Sprintf("/api/v1/projects/%s/environments/%s/secrets",
			url.PathEscape(projectID), url.PathEscape(environmentID)),
		body: input,
		out:  &secret,
	})
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// UpdateSecret writes a new version of a secret.
//
// expectedVersion enables optimistic concurrency via If-Match: when non-zero
// the write fails with a 409 if another writer has bumped the version since it
// was read. Pass 0 to overwrite unconditionally.
func (c *Client) UpdateSecret(ctx context.Context, secretID string, input UpdateSecretInput, expectedVersion int) (*Secret, error) {
	if err := requireID("secret id", secretID); err != nil {
		return nil, err
	}
	req := request{
		method: http.MethodPatch,
		path:   "/api/v1/secrets/" + url.PathEscape(secretID),
		body:   input,
	}
	var secret Secret
	req.out = &secret
	if expectedVersion > 0 {
		req.headers = map[string]string{"If-Match": strconv.Quote(strconv.Itoa(expectedVersion))}
	}
	if _, err := c.do(ctx, req); err != nil {
		return nil, err
	}
	return &secret, nil
}

// DeleteSecret soft-deletes a secret.
func (c *Client) DeleteSecret(ctx context.Context, secretID string) error {
	if err := requireID("secret id", secretID); err != nil {
		return err
	}
	_, err := c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/api/v1/secrets/" + url.PathEscape(secretID),
	})
	return err
}

// ---- API keys ----

// ListAPIKeys returns every API key in the organization.
func (c *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	return listAll[APIKey](ctx, c, "/api/v1/api-keys", nil)
}

// GetAPIKey fetches one API key's metadata by id. The API exposes no
// single-key endpoint, so this filters the listing.
func (c *Client) GetAPIKey(ctx context.Context, apiKeyID string) (*APIKey, error) {
	if err := requireID("api key id", apiKeyID); err != nil {
		return nil, err
	}
	keys, err := c.ListAPIKeys(ctx)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].ID == apiKeyID {
			return &keys[i], nil
		}
	}
	return nil, &Error{
		StatusCode: http.StatusNotFound,
		Code:       "NOT_FOUND",
		Message:    fmt.Sprintf("api key %s not found", apiKeyID),
	}
}

// CreateAPIKey mints a token. The plaintext token in the result is returned
// only here and cannot be retrieved again.
func (c *Client) CreateAPIKey(ctx context.Context, input CreateAPIKeyInput) (*CreatedAPIKey, error) {
	if input.EnvironmentID != nil && input.ProjectID == nil {
		return nil, errors.New("himitsu: environment-scoped API keys require a project id")
	}
	var created CreatedAPIKey
	_, err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/api-keys",
		body:   input,
		out:    &created,
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// RevokeAPIKey permanently revokes a token. Revocation is idempotent.
func (c *Client) RevokeAPIKey(ctx context.Context, apiKeyID string) error {
	if err := requireID("api key id", apiKeyID); err != nil {
		return err
	}
	_, err := c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/api/v1/api-keys/" + url.PathEscape(apiKeyID),
	})
	return err
}

// ---- Tags ----

// ListTags returns every tag in the organization.
func (c *Client) ListTags(ctx context.Context) ([]Tag, error) {
	return listAll[Tag](ctx, c, "/api/v1/tags", nil)
}

// GetTag fetches one tag by id from the listing.
func (c *Client) GetTag(ctx context.Context, tagID string) (*Tag, error) {
	if err := requireID("tag id", tagID); err != nil {
		return nil, err
	}
	tags, err := c.ListTags(ctx)
	if err != nil {
		return nil, err
	}
	for i := range tags {
		if tags[i].ID == tagID {
			return &tags[i], nil
		}
	}
	return nil, &Error{
		StatusCode: http.StatusNotFound,
		Code:       "NOT_FOUND",
		Message:    fmt.Sprintf("tag %s not found", tagID),
	}
}

// CreateTag creates a tag.
func (c *Client) CreateTag(ctx context.Context, input CreateTagInput) (*Tag, error) {
	var tag Tag
	_, err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/tags",
		body:   input,
		out:    &tag,
	})
	if err != nil {
		return nil, err
	}
	return &tag, nil
}

// UpdateTag applies a partial update.
func (c *Client) UpdateTag(ctx context.Context, tagID string, input UpdateTagInput) (*Tag, error) {
	if err := requireID("tag id", tagID); err != nil {
		return nil, err
	}
	var tag Tag
	_, err := c.do(ctx, request{
		method: http.MethodPatch,
		path:   "/api/v1/tags/" + url.PathEscape(tagID),
		body:   input,
		out:    &tag,
	})
	if err != nil {
		return nil, err
	}
	return &tag, nil
}

// DeleteTag removes a tag and detaches it from every resource.
func (c *Client) DeleteTag(ctx context.Context, tagID string) error {
	if err := requireID("tag id", tagID); err != nil {
		return err
	}
	_, err := c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/api/v1/tags/" + url.PathEscape(tagID),
	})
	return err
}
