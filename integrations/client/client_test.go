package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "himi_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// newTestClient wires a client to a test server with retry sleeps disabled so
// the retry loop runs at full speed.
func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c, err := New(server.URL, testToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c, server
}

func TestNewValidatesInput(t *testing.T) {
	cases := []struct {
		name, url, token, wantErr string
	}{
		{"empty url", "", testToken, "API URL is required"},
		{"bad scheme", "ftp://example.com", testToken, "must use http or https"},
		{"no host", "https://", testToken, "must include a host"},
		{"short token", "https://example.com", "himi_abc_short", "malformed"},
		{"empty token", "https://example.com", "", "malformed"},
		{"non-hex id", "https://example.com", "himi_zzzzzzzzzzzzzzzz_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.url, tc.token); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
	if _, err := New("https://example.com/", testToken); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
}

func TestBaseURLPathPrefixIsPreserved(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{"data": Project{ID: "p1"}})
	}))
	defer server.Close()

	// A Himitsu deployment behind a path-prefixed reverse proxy must still work.
	c, err := New(server.URL+"/himitsu/", testToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.GetProject(context.Background(), "p1"); err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if want := "/himitsu/api/v1/projects/p1"; gotPath != want {
		t.Fatalf("path = %q, want %q", gotPath, want)
	}
}

func TestAuthorizationHeaderIsSent(t *testing.T) {
	var gotAuth, gotAgent string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAgent = r.Header.Get("User-Agent")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": Project{ID: "p1"}})
	}))
	if _, err := c.GetProject(context.Background(), "p1"); err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if want := "Bearer " + testToken; gotAuth != want {
		t.Fatalf("Authorization = %q, want %q", gotAuth, want)
	}
	if !strings.HasPrefix(gotAgent, "himitsu-go-client/") {
		t.Fatalf("User-Agent = %q", gotAgent)
	}
}

func TestErrorEnvelopeIsDecoded(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
			"code": "API_SCOPE_FORBIDDEN", "message": "API key scope does not match", "requestId": "req-42",
		}})
	}))
	_, err := c.GetProject(context.Background(), "p1")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsForbidden(err) {
		t.Fatalf("IsForbidden = false for %v", err)
	}
	if got := ErrorCode(err); got != "API_SCOPE_FORBIDDEN" {
		t.Fatalf("ErrorCode = %q", got)
	}
	if !strings.Contains(err.Error(), "req-42") {
		t.Fatalf("request id missing from %q", err.Error())
	}
}

func TestNonJSONErrorBodyIsSurfaced(t *testing.T) {
	// A gateway answering instead of the API must not produce a confusing
	// "unknown error" with no diagnostic content.
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	c.maxAttempts = 1
	_, err := c.GetProject(context.Background(), "p1")
	if err == nil || !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("expected gateway body in error, got %v", err)
	}
}

func TestNotFoundIsClassified(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
			"code": "NOT_FOUND", "message": "Project not found", "requestId": "r1",
		}})
	}))
	_, err := c.GetProject(context.Background(), "missing")
	if !IsNotFound(err) {
		t.Fatalf("IsNotFound = false for %v", err)
	}
}

func TestRetriesOn5xxThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
				"code": "INTERNAL", "message": "boom", "requestId": "r1",
			}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": Project{ID: "p1", Name: "recovered"}})
	}))
	project, err := c.GetProject(context.Background(), "p1")
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if project.Name != "recovered" || calls.Load() != 3 {
		t.Fatalf("name=%q calls=%d", project.Name, calls.Load())
	}
}

func TestRetriesOn429(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("RateLimit-Reset", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
				"code": "RATE_LIMITED", "message": "slow down", "requestId": "r1",
			}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": Project{ID: "p1"}})
	}))
	if _, err := c.GetProject(context.Background(), "p1"); err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}

func TestDoesNotRetryOn4xx(t *testing.T) {
	// Retrying a 403 only burns rate-limit budget; the answer will not change.
	var calls atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
			"code": "FORBIDDEN", "message": "no", "requestId": "r1",
		}})
	}))
	if _, err := c.GetProject(context.Background(), "p1"); err == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	if _, err := c.GetProject(context.Background(), "p1"); err == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != int32(defaultMaxAttempts) {
		t.Fatalf("calls = %d, want %d", calls.Load(), defaultMaxAttempts)
	}
}

func TestRetriedRequestReplaysBody(t *testing.T) {
	// A retried POST must resend its body; a consumed reader would send zero bytes.
	var bodies []string
	var calls atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": Project{ID: "p1"}})
	}))
	if _, err := c.CreateProject(context.Background(), CreateProjectInput{Name: "App", Slug: "app"}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if len(bodies) != 2 || bodies[0] != bodies[1] || !strings.Contains(bodies[0], `"slug":"app"`) {
		t.Fatalf("bodies = %#v", bodies)
	}
}

func TestContextCancellationStopsRetries(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	// Restore a real sleep so cancellation has something to interrupt.
	c.sleep = sleepContext
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.GetProject(ctx, "p1"); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestRuntimeConfigFullFetch(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/api/v1/projects/p1/environments/e1/secrets/runtime" {
			t.Errorf("path = %q", got)
		}
		if r.Header.Get("If-None-Match") != "" {
			t.Error("If-None-Match sent for an unconditional fetch")
		}
		w.Header().Set("ETag", `"himi-config-7"`)
		w.Header().Set("X-Himitsu-Config-Version", "7")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"configVersion": 7,
			"secrets":       map[string]string{"DATABASE_URL": "postgres://x", "API_KEY": "k"},
		}})
	}))
	config, err := c.RuntimeConfig(context.Background(), "p1", "e1", 0)
	if err != nil {
		t.Fatalf("RuntimeConfig: %v", err)
	}
	if config.NotModified {
		t.Fatal("NotModified should be false on a 200")
	}
	if config.ConfigVersion != 7 || len(config.Secrets) != 2 || config.Secrets["API_KEY"] != "k" {
		t.Fatalf("config = %+v", config)
	}
}

func TestRuntimeConfigNotModified(t *testing.T) {
	var gotIfNoneMatch string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("X-Himitsu-Config-Version", "7")
		w.WriteHeader(http.StatusNotModified)
	}))
	config, err := c.RuntimeConfig(context.Background(), "p1", "e1", 7)
	if err != nil {
		t.Fatalf("RuntimeConfig: %v", err)
	}
	if gotIfNoneMatch != `"himi-config-7"` {
		t.Fatalf("If-None-Match = %q", gotIfNoneMatch)
	}
	if !config.NotModified || config.ConfigVersion != 7 {
		t.Fatalf("config = %+v", config)
	}
	// Secrets must stay nil so callers cannot mistake a 304 for an emptied
	// environment and wipe a live Kubernetes Secret.
	if config.Secrets != nil {
		t.Fatalf("Secrets = %v, want nil on 304", config.Secrets)
	}
}

func TestRuntimeConfigEmptyEnvironmentIsNotNil(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Himitsu-Config-Version", "3")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"configVersion": 3, "secrets": map[string]string{},
		}})
	}))
	config, err := c.RuntimeConfig(context.Background(), "p1", "e1", 0)
	if err != nil {
		t.Fatalf("RuntimeConfig: %v", err)
	}
	if config.Secrets == nil || len(config.Secrets) != 0 {
		t.Fatalf("Secrets = %v, want empty non-nil", config.Secrets)
	}
}

func TestRuntimeConfigHeaderOverridesBodyVersion(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Himitsu-Config-Version", "9")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"configVersion": 4, "secrets": map[string]string{"A": "1"},
		}})
	}))
	config, err := c.RuntimeConfig(context.Background(), "p1", "e1", 0)
	if err != nil {
		t.Fatalf("RuntimeConfig: %v", err)
	}
	if config.ConfigVersion != 9 {
		t.Fatalf("ConfigVersion = %d, want 9 (header wins)", config.ConfigVersion)
	}
}

func TestRuntimeConfigRequiresIDs(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not reach the server")
	}))
	if _, err := c.RuntimeConfig(context.Background(), "", "e1", 0); err == nil {
		t.Fatal("expected error for empty project id")
	}
	if _, err := c.RuntimeConfig(context.Background(), "p1", "", 0); err == nil {
		t.Fatal("expected error for empty environment id")
	}
}

func TestListPaginatesUntilExhausted(t *testing.T) {
	total := 250
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset := 0
		_, _ = fmt.Sscanf(r.URL.Query().Get("offset"), "%d", &offset)
		items := []Project{}
		for i := offset; i < offset+pageSize && i < total; i++ {
			items = append(items, Project{ID: fmt.Sprintf("p%d", i)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": items,
			"meta": map[string]int{"limit": pageSize, "offset": offset, "total": total},
		})
	}))
	projects, err := c.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != total {
		t.Fatalf("got %d projects, want %d", len(projects), total)
	}
	if projects[249].ID != "p249" {
		t.Fatalf("last project = %q", projects[249].ID)
	}
}

func TestListStopsOnShortPageDespiteBadTotal(t *testing.T) {
	// A stale or wrong meta.total must not spin the pagination loop forever.
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []Project{{ID: "p1"}},
			"meta": map[string]int{"limit": pageSize, "offset": 0, "total": 9999},
		})
	}))
	projects, err := c.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("got %d projects, want 1", len(projects))
	}
}

func TestUpdateSecretSendsIfMatch(t *testing.T) {
	var gotIfMatch string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfMatch = r.Header.Get("If-Match")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": Secret{ID: "s1", CurrentVersion: 4}})
	}))
	if _, err := c.UpdateSecret(context.Background(), "s1", UpdateSecretInput{Value: "v"}, 3); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if gotIfMatch != `"3"` {
		t.Fatalf("If-Match = %q, want \"3\"", gotIfMatch)
	}
}

func TestUpdateSecretOmitsIfMatchWhenUnversioned(t *testing.T) {
	var gotIfMatch string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfMatch = r.Header.Get("If-Match")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": Secret{ID: "s1"}})
	}))
	if _, err := c.UpdateSecret(context.Background(), "s1", UpdateSecretInput{Value: "v"}, 0); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if gotIfMatch != "" {
		t.Fatalf("If-Match = %q, want empty", gotIfMatch)
	}
}

func TestFindSecretByKeyReturnsNotFound(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []Secret{{ID: "s1", Key: "PRESENT"}},
			"meta": map[string]int{"limit": pageSize, "offset": 0, "total": 1},
		})
	}))
	found, err := c.FindSecretByKey(context.Background(), "p1", "e1", "PRESENT")
	if err != nil || found.ID != "s1" {
		t.Fatalf("FindSecretByKey(PRESENT) = %v, %v", found, err)
	}
	if _, err := c.FindSecretByKey(context.Background(), "p1", "e1", "ABSENT"); !IsNotFound(err) {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

func TestCreateAPIKeyRejectsEnvironmentWithoutProject(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not reach the server")
	}))
	_, err := c.CreateAPIKey(context.Background(), CreateAPIKeyInput{
		Name: "ci", Access: AccessReadOnly, EnvironmentID: Ptr("e1"),
	})
	if err == nil || !strings.Contains(err.Error(), "require a project id") {
		t.Fatalf("expected scope validation error, got %v", err)
	}
}

func TestExportRejectsUnknownFormat(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not reach the server")
	}))
	if _, err := c.Export(context.Background(), "p1", "e1", ExportFormat("yaml"), false, ""); err == nil {
		t.Fatal("expected format validation error")
	}
}

func TestExportBuildsQuery(t *testing.T) {
	var gotQuery string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{"data": Export{
			Format: FormatJSON, Content: "{}", SecretCount: 0,
		}})
	}))
	if _, err := c.Export(context.Background(), "p1", "e1", FormatJSON, true, "."); err != nil {
		t.Fatalf("Export: %v", err)
	}
	for _, want := range []string{"format=json", "nested=true", "delimiter=."} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
}

func TestBackoffHonoursRetryAfterHint(t *testing.T) {
	err := &Error{StatusCode: 429, Details: map[string]any{"retryAfterSeconds": float64(2)}}
	if got := backoff(2, err); got != 2*time.Second {
		t.Fatalf("backoff = %v, want 2s", got)
	}
	// The hint is capped so a hostile or broken value cannot stall a reconcile.
	capped := &Error{StatusCode: 429, Details: map[string]any{"retryAfterSeconds": float64(3600)}}
	if got := backoff(2, capped); got > 8*time.Second {
		t.Fatalf("backoff = %v, want <= 8s", got)
	}
}

func TestBackoffGrowsAndStaysBounded(t *testing.T) {
	for attempt := 2; attempt <= 10; attempt++ {
		if got := backoff(attempt, nil); got <= 0 || got > 8*time.Second {
			t.Fatalf("backoff(%d) = %v, out of bounds", attempt, got)
		}
	}
}

func TestRuntimeETagFormat(t *testing.T) {
	if got := runtimeETag(42); got != `"himi-config-42"` {
		t.Fatalf("runtimeETag = %q", got)
	}
}
