package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/logger"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
)

// Recovery turns a panic into a JSON 500 and a log line. It has to be the
// outermost middleware, or a panic in a wrapper escapes it.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered",
					"error", rec,
					"stack", string(debug.Stack()),
					"route", r.Pattern,
					"method", r.Method,
				)
				response.Error(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
