package requestctx

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const (
	userIDKey    contextKey = "user_id"
	orgIDKey     contextKey = "org_id"
	requestIDKey contextKey = "request_id"
	sessionIDKey contextKey = "session_id"
)

// WithUserID attaches the authenticated user's ID to the request context.
// Set once, by authn middleware, after a successful token lookup.
func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// UserID reads the authenticated user's ID. ok is false if authn
// middleware hasn't run yet — callers must check it rather than assuming
// a zero-value UUID means "unauthenticated."
func UserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

// WithOrgID attaches the organization ID a request has been authorized
// against. Set once, by authz middleware, after the route's org_id has
// been validated against the user's memberships — never set this from an
// unvalidated route parameter directly.
func WithOrgID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, orgIDKey, id)
}

// OrgID reads the authorized organization ID. ok is false if authz
// middleware hasn't run (or the route has no org scope).
func OrgID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(orgIDKey).(uuid.UUID)
	return id, ok
}

// WithRequestID attaches the request ID. Set once, by RequestLogger, at
// the very start of the chain — everything downstream (handlers, error
// responses, other logging) reads it from context, not from the request
// header directly.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID reads the request ID. ok is false if RequestLogger hasn't run.
func RequestID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey).(string)
	return id, ok
}

// WithSessionID attaches the current session's ID — set once, by Authn,
// alongside the user ID. Logout uses this to revoke exactly the session
// the caller is currently using, without a second token-hash lookup.
func WithSessionID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, sessionIDKey, id)
}

func SessionID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(sessionIDKey).(uuid.UUID)
	return id, ok
}
