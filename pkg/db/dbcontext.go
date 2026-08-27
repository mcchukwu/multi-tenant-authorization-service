package db

import (
	"context"
	"time"
)

const DefaultQueryTimeout = 5 * time.Second

func WithDBTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, DefaultQueryTimeout)
}
