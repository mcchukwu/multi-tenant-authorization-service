package requestctx

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const userIDKey contextKey = "user_id"

// WithUserID attaches the authenticated user's ID to the request context.
// Set once, by authn middleware, after a successful token lookup — every
// handler and authz middleware downstream reads it from here rather than
// re-deriving it.
func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// UserID reads the authenticated user's ID. ok is false if no authn
// middleware has run yet — callers must check it rather than assuming a
// zero-value UUID means "unauthenticated," since that's a silent bug
// waiting to grant zero-value-shaped access.
func UserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}
