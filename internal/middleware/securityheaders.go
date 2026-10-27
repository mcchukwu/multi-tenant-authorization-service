package middleware

import "net/http"

// SecurityHeaders targets a JSON-only origin. The CSP assumes nothing is
// served from here that should load a script, style or frame.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// HSTS is what backs up the Secure flag during the first request.
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		w.Header().Set("X-XSS-Protection", "1; mode=block")

		next.ServeHTTP(w, r)
	})
}
