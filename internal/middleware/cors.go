package middleware

import "net/http"

type CORSConfig struct {
	AllowedOrigins []string
}

// CORS echoes back the exact validated origin rather than "*", this
// isn't a stylistic choice, browsers flatly reject the combination of
// Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials:
// true, and this API needs credentials (cookies) allowed since that's
// how the refresh token travels.
func CORS(cfg CORSConfig) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowed[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				// Vary: Origin — this response differs based on the
				// request's Origin header, so caches must key on it too,
				// or a cache could serve one origin's CORS headers to a
				// different origin's request.
				w.Header().Set("Vary", "Origin")
			}

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
