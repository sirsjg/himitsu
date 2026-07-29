// Package client is a Go SDK for the Himitsu REST API v1.
//
// It is shared by the Kubernetes operator and the Terraform provider. Both need
// the same three things from the API and nothing else agrees on them: the
// `{"data":…}` success envelope, the `{"error":…}` failure envelope, and the
// ETag/config-version protocol on the runtime endpoint.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout     = 30 * time.Second
	defaultMaxAttempts = 4
	defaultUserAgent   = "himitsu-go-client/1.0"

	// maxErrorBody caps how much of a non-JSON error response we read, so a
	// misrouted request that returns an HTML page cannot balloon memory.
	maxErrorBody = 64 << 10
)

// tokenPattern mirrors the server-side format in packages/api-keys: a
// himi_-prefixed 16 hex character id and a 43 character base64url secret.
var tokenPattern = regexp.MustCompile(`^himi_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$`)

// Client is a Himitsu API client. It is safe for concurrent use.
type Client struct {
	baseURL     *url.URL
	token       string
	httpClient  *http.Client
	userAgent   string
	maxAttempts int
	// sleep is indirected so tests can run the retry loop without wall-clock delay.
	sleep func(context.Context, time.Duration) error
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient replaces the underlying HTTP client. Use it to install custom
// TLS roots, proxies, or instrumentation.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// WithUserAgent sets the User-Agent header. The operator and provider each
// identify themselves so API audit events attribute traffic correctly.
func WithUserAgent(userAgent string) Option {
	return func(c *Client) {
		if strings.TrimSpace(userAgent) != "" {
			c.userAgent = userAgent
		}
	}
}

// WithMaxAttempts bounds total tries per request, including the first. A value
// below 1 is ignored.
func WithMaxAttempts(attempts int) Option {
	return func(c *Client) {
		if attempts >= 1 {
			c.maxAttempts = attempts
		}
	}
}

// New builds a client for baseURL authenticating with a Himitsu API token.
//
// The token format is validated locally so that a malformed or truncated
// credential fails at construction with a clear message, rather than as an
// opaque 401 on every subsequent reconcile.
func New(baseURL, token string, opts ...Option) (*Client, error) {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return nil, errors.New("himitsu: API URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("himitsu: API URL is invalid: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("himitsu: API URL must use http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, errors.New("himitsu: API URL must include a host")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")

	if !tokenPattern.MatchString(strings.TrimSpace(token)) {
		return nil, errors.New("himitsu: API token is malformed (expected himi_<16 hex>_<43 chars>)")
	}

	c := &Client{
		baseURL:     parsed,
		token:       strings.TrimSpace(token),
		httpClient:  &http.Client{Timeout: defaultTimeout},
		userAgent:   defaultUserAgent,
		maxAttempts: defaultMaxAttempts,
		sleep:       sleepContext,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// envelope is the success wrapper every v1 endpoint returns.
type envelope struct {
	Data json.RawMessage `json:"data"`
	Meta struct {
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
		Total  int `json:"total"`
	} `json:"meta"`
}

type errorEnvelope struct {
	Error struct {
		Code      string         `json:"code"`
		Message   string         `json:"message"`
		RequestID string         `json:"requestId"`
		Details   map[string]any `json:"details"`
	} `json:"error"`
}

// request describes a single API call.
type request struct {
	method string
	path   string
	query  url.Values
	body   any
	// headers are applied after the defaults, so they may override them.
	headers map[string]string
	// out receives the decoded `data` field when non-nil.
	out any
	// meta receives pagination metadata when non-nil.
	meta *envelope
	// okStatus lists additional non-2xx statuses the caller handles itself.
	// 304 on the runtime endpoint is the only current use.
	okStatus []int
}

func (c *Client) do(ctx context.Context, req request) (*http.Response, error) {
	var encoded []byte
	if req.body != nil {
		var err error
		encoded, err = json.Marshal(req.body)
		if err != nil {
			return nil, fmt.Errorf("himitsu: encoding request body: %w", err)
		}
	}

	endpoint := *c.baseURL
	endpoint.Path = c.baseURL.Path + req.path
	if len(req.query) > 0 {
		endpoint.RawQuery = req.query.Encode()
	}

	var lastErr error
	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		if attempt > 1 {
			if err := c.sleep(ctx, backoff(attempt, lastErr)); err != nil {
				return nil, err
			}
		}

		var reader io.Reader
		if encoded != nil {
			// A fresh reader per attempt: a retried request must replay the body.
			reader = bytes.NewReader(encoded)
		}
		httpReq, err := http.NewRequestWithContext(ctx, req.method, endpoint.String(), reader)
		if err != nil {
			return nil, fmt.Errorf("himitsu: building request: %w", err)
		}
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
		httpReq.Header.Set("Accept", "application/json")
		httpReq.Header.Set("User-Agent", c.userAgent)
		if encoded != nil {
			httpReq.Header.Set("Content-Type", "application/json")
		}
		for name, value := range req.headers {
			httpReq.Header.Set(name, value)
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			// Transport failures are retryable: the operator reconciles against
			// a network that may be briefly unavailable.
			lastErr = fmt.Errorf("himitsu: %s %s: %w", req.method, req.path, err)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}

		done, err := c.handle(resp, req)
		if done {
			return resp, err
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New("himitsu: request failed")
	}
	return nil, fmt.Errorf("after %d attempts: %w", c.maxAttempts, lastErr)
}

// handle processes one response. It reports whether the outcome is final; when
// false the caller retries with the returned error as context.
func (c *Client) handle(resp *http.Response, req request) (bool, error) {
	defer func() {
		// Drain so the connection returns to the keep-alive pool.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		_ = resp.Body.Close()
	}()

	for _, status := range req.okStatus {
		if resp.StatusCode == status {
			return true, nil
		}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if req.out == nil && req.meta == nil {
			return true, nil
		}
		var env envelope
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			return true, fmt.Errorf("himitsu: decoding %s %s response: %w", req.method, req.path, err)
		}
		if req.meta != nil {
			*req.meta = env
		}
		if req.out != nil {
			if len(env.Data) == 0 {
				return true, fmt.Errorf("himitsu: %s %s returned no data field", req.method, req.path)
			}
			if err := json.Unmarshal(env.Data, req.out); err != nil {
				return true, fmt.Errorf("himitsu: decoding %s %s data: %w", req.method, req.path, err)
			}
		}
		return true, nil
	}

	apiErr := decodeError(resp)
	// 429 and 5xx are transient; everything else is the caller's problem and
	// retrying would only burn rate-limit budget.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return false, apiErr
	}
	return true, apiErr
}

func decodeError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	apiErr := &Error{
		StatusCode: resp.StatusCode,
		Code:       "UNKNOWN",
		Message:    strings.TrimSpace(http.StatusText(resp.StatusCode)),
	}
	var decoded errorEnvelope
	if err := json.Unmarshal(body, &decoded); err == nil && decoded.Error.Code != "" {
		apiErr.Code = decoded.Error.Code
		apiErr.Message = decoded.Error.Message
		apiErr.RequestID = decoded.Error.RequestID
		apiErr.Details = decoded.Error.Details
	} else if len(body) > 0 {
		// Non-JSON body: a proxy or gateway answered instead of the API.
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		apiErr.Message = snippet
	}
	if retryAfter := retryAfterDuration(resp); retryAfter > 0 {
		apiErr.Details = withRetryAfter(apiErr.Details, retryAfter)
	}
	return apiErr
}

func withRetryAfter(details map[string]any, d time.Duration) map[string]any {
	if details == nil {
		details = map[string]any{}
	}
	details["retryAfterSeconds"] = d.Seconds()
	return details
}

// retryAfterDuration reads the server's own backoff hint. Himitsu emits
// RateLimit-Reset (seconds) on throttled responses; Retry-After is honoured too
// because reverse proxies in front of the API commonly add it.
func retryAfterDuration(resp *http.Response) time.Duration {
	for _, header := range []string{"Retry-After", "RateLimit-Reset"} {
		value := strings.TrimSpace(resp.Header.Get(header))
		if value == "" {
			continue
		}
		if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
			return time.Duration(seconds) * time.Second
		}
		if at, err := http.ParseTime(value); err == nil {
			if d := time.Until(at); d > 0 {
				return d
			}
		}
	}
	return 0
}

// backoff returns the delay before the given attempt. It prefers the server's
// Retry-After hint and otherwise uses exponential backoff with jitter, capped
// so a wedged control plane cannot stall a reconcile indefinitely.
func backoff(attempt int, lastErr error) time.Duration {
	const (
		base  = 250 * time.Millisecond
		limit = 8 * time.Second
	)
	if apiErr, ok := asError(lastErr); ok && apiErr.Details != nil {
		if seconds, ok := apiErr.Details["retryAfterSeconds"].(float64); ok && seconds > 0 {
			hint := time.Duration(seconds * float64(time.Second))
			if hint > limit {
				return limit
			}
			return hint
		}
	}
	exponent := math.Pow(2, float64(attempt-2)) // attempt 2 -> 1x base
	delay := time.Duration(float64(base) * exponent)
	if delay > limit || delay <= 0 {
		delay = limit
	}
	// Jitter within [delay/2, delay] decorrelates retries across operator
	// replicas while keeping the result bounded by the cap.
	half := int64(delay) / 2
	if half <= 0 {
		return delay
	}
	return time.Duration(half + rand.Int63n(half))
}
