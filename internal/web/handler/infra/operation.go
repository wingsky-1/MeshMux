package infra

import (
	"context"
	"net/http"

	"github.com/wingsky-1/MeshMux/internal/control/store"
)

// Operation returns the operation identifier assigned to one request. It is the
// only per-request value that may appear in a log line and in a response
// header; it never carries the path, the form or the bearer.
func Operation(r *http.Request) string {
	v, _ := r.Context().Value(operationKey).(string)
	return v
}

// WithOperation returns a request carrying op.
func WithOperation(r *http.Request, op string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), operationKey, op))
}

// AssignOperation returns a request that has an operation id, adding one only
// when the management boundary has not already assigned it. The subscription
// download runs outside that boundary, so it assigns its own.
func AssignOperation(r *http.Request) *http.Request {
	if Operation(r) != "" {
		return r
	}
	return WithOperation(r, NewOperation())
}

// NewOperation mints one operation id.
func NewOperation() string { return store.RandomToken()[:22] }
