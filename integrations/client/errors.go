package client

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is a structured failure returned by the Himitsu API. It mirrors the
// `{"error":{code,message,requestId}}` envelope every non-2xx response carries.
type Error struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	Details    map[string]any
}

func (e *Error) Error() string {
	if e.RequestID == "" {
		return fmt.Sprintf("himitsu: %s (%s, http %d)", e.Message, e.Code, e.StatusCode)
	}
	return fmt.Sprintf("himitsu: %s (%s, http %d, request %s)", e.Message, e.Code, e.StatusCode, e.RequestID)
}

// asError unwraps err into a *Error when possible.
func asError(err error) (*Error, bool) {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

// IsNotFound reports whether err is a 404 from the API. Callers use this to
// drive Terraform state removal and operator "resource vanished" handling.
func IsNotFound(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusNotFound
}

// IsForbidden reports whether err is a 403. Distinguishing this from 404 keeps
// scope errors ("API key does not cover this project") legible to operators
// rather than silently deleting state.
func IsForbidden(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusForbidden
}

// IsUnauthorized reports whether err is a 401, meaning the token is invalid,
// revoked, or expired.
func IsUnauthorized(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusUnauthorized
}

// IsConflict reports whether err is a 409, which the API returns for optimistic
// concurrency failures (If-Match version mismatch) and slug collisions.
func IsConflict(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusConflict
}

// ErrorCode returns the stable machine-readable code from an API error, or ""
// when err did not originate from the API.
func ErrorCode(err error) string {
	if apiErr, ok := asError(err); ok {
		return apiErr.Code
	}
	return ""
}
