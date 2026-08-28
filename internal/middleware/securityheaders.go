package middleware

import "net/http"

// SecurityHeaders sets response headers appropriate for a pure JSON API
// with no HTML rendering surface, the CSP in particular is intentionally
// aggressive (default-src 'none') since there's nothing here that should
// ever load a script, style, or frame.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stops the browser from guessing content types and executing
		// something unexpected based on that guess.
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Refuses to let this API's responses be framed by anyone
		// relevant defense-in-depth alongside CSRF: clickjacking is a
		// related attack class (trick a user into an unintended action
		// via a hidden frame) that SameSite cookies don't address.
		w.Header().Set("X-Frame-Options", "DENY")

		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Forces HTTPS for a year, including subdomains, this backs up
		// the Secure flag on your session cookies: a cookie marked
		// Secure is simply never sent over plain HTTP, and HSTS is what
		// stops a client from ever downgrading to plain HTTP in the
		// first place.
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Basic XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		next.ServeHTTP(w, r)
	})
}
