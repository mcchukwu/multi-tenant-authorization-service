package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

// Recovery does not, by itself, prevent a panic from taking down the
// server, Go's net/http already recovers per-request panics and closes
// the connection, so the process was never actually at risk. What this
// buys you instead: a clean JSON error response (instead of an abruptly
// reset connection the client has to interpret as a network failure) and
// a structured log line with a stack trace, instead of net/http's default
// unstructured stderr output.
//
// Must be the outermost middleware in the chain — anything registered
// inside it (including other middleware) is covered by this recover;
// anything outside it isn't.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered",
					"error", rec,
					"stack", string(debug.Stack()),
					"path", r.URL.Path,
					"method", r.Method,
				)
				response.Error(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
