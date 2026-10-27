package middleware

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/logger"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/requestctx"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/utils"
)

// statusRecorder captures the status code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// RequestLogger adds an X-Request-ID and logs one line per request.
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

		// Matched pattern, not the raw path: tokens live in URLs.
		route := r.Pattern
		if route == "" {
			route = r.URL.Path
		}

		logger.Info("request",
			"request_id", requestID,
			"method", r.Method,
			"route", route,
			"status", wrapped.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", utils.ClientIP(r),
		)
	})
}
