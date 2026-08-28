package middleware

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/requestctx"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/utils"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

// statusRecorder captures the status code a handler writes — the stdlib
// ResponseWriter doesn't expose this after the fact, so wrapping it is
// the standard way to find out what actually got sent.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// RequestLogger generates a request ID if the client didn't supply one,
// sets it on both the incoming request and the
// response (so the client can reference it in a support request), then
// logs method/path/status/duration once the request completes.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.NewString()
		}
		ctx := requestctx.WithRequestID(r.Context(), requestID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", requestID)

		start := time.Now()
		wrapped := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		logger.Info("request",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", utils.ClientIP(r),
		)
	})
}
