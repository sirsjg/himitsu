package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// runtimeETag renders a config version in the server's ETag format. It matches
// runtimeEtag() in apps/api/src/index.ts.
func runtimeETag(configVersion int64) string {
	return fmt.Sprintf("%q", "himi-config-"+strconv.FormatInt(configVersion, 10))
}

// parseConfigVersion reads the X-Himitsu-Config-Version header, which the API
// sets on both 200 and 304 responses. It is the only way to learn the version
// from a 304, whose body is empty.
func parseConfigVersion(resp *http.Response) (int64, bool) {
	raw := strings.TrimSpace(resp.Header.Get("X-Himitsu-Config-Version"))
	if raw == "" {
		return 0, false
	}
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || version < 0 {
		return 0, false
	}
	return version, true
}

// RuntimeConfig fetches every secret in an environment as a flat map.
//
// knownVersion enables conditional fetching: pass the version from a previous
// call and the server answers 304 with NotModified set, transferring no secret
// material and recording no audit read. Pass 0 to force a full fetch.
//
// This is the endpoint the Kubernetes operator polls on every reconcile, so the
// 304 path is the common case in steady state.
func (c *Client) RuntimeConfig(ctx context.Context, projectID, environmentID string, knownVersion int64) (*RuntimeConfig, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	if err := requireID("environment id", environmentID); err != nil {
		return nil, err
	}

	var config RuntimeConfig
	req := request{
		method: http.MethodGet,
		path: fmt.Sprintf("/api/v1/projects/%s/environments/%s/secrets/runtime",
			url.PathEscape(projectID), url.PathEscape(environmentID)),
		out:      &config,
		okStatus: []int{http.StatusNotModified},
	}
	if knownVersion > 0 {
		req.headers = map[string]string{"If-None-Match": runtimeETag(knownVersion)}
	}

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotModified {
		version := knownVersion
		if reported, ok := parseConfigVersion(resp); ok {
			version = reported
		}
		return &RuntimeConfig{ConfigVersion: version, NotModified: true}, nil
	}

	// Trust the header over the body when both are present: it is the value the
	// ETag was derived from.
	if reported, ok := parseConfigVersion(resp); ok {
		config.ConfigVersion = reported
	}
	if config.Secrets == nil {
		config.Secrets = map[string]string{}
	}
	return &config, nil
}

// Export renders an environment in dotenv, JSON, or shell form.
//
// nested applies to the JSON format only, re-expanding delimiter-separated keys
// into nested objects; delimiter defaults to "__" when empty.
func (c *Client) Export(ctx context.Context, projectID, environmentID string, format ExportFormat, nested bool, delimiter string) (*Export, error) {
	if err := requireID("project id", projectID); err != nil {
		return nil, err
	}
	if err := requireID("environment id", environmentID); err != nil {
		return nil, err
	}
	switch format {
	case FormatDotenv, FormatJSON, FormatShell:
	default:
		return nil, fmt.Errorf("himitsu: export format must be dotenv, json, or shell, got %q", format)
	}

	query := url.Values{"format": []string{string(format)}}
	if nested {
		query.Set("nested", "true")
	}
	if delimiter != "" {
		query.Set("delimiter", delimiter)
	}

	var export Export
	_, err := c.do(ctx, request{
		method: http.MethodGet,
		path: fmt.Sprintf("/api/v1/projects/%s/environments/%s/exports",
			url.PathEscape(projectID), url.PathEscape(environmentID)),
		query: query,
		out:   &export,
	})
	if err != nil {
		return nil, err
	}
	return &export, nil
}
