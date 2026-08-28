package auth

import (
	"crypto/subtle"
	"net/http"
	"time"
)

const (
	refreshCookieName = "refresh_token"
	csrfCookieName    = "csrf_token"
	authCookiePath    = "/v1/auth"
)

// setAuthCookies sets both the httpOnly refresh-token cookie and the
// JS-readable CSRF cookie together. One place, used by every handler that
// issues a session (login, register, refresh), so the two cookies can
// never drift out of sync by being set inline in three different files.
func setAuthCookies(w http.ResponseWriter, refreshToken, csrfToken string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    refreshToken,
		Path:     authCookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfToken,
		Path:     authCookiePath,
		HttpOnly: false, // must be readable by JS — it's echoed back in a header, not a secret credential on its own
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
	})
}

// verifyCSRF implements the double-submit cookie pattern: the client must
// echo the csrf_token cookie's value back in the X-CSRF-Token header. A
// cross-site attacker can trigger the browser to send the cookie
// automatically on a forged request, but cannot read its value to also
// set the matching header, same-origin script access to document.cookie
// is what actually blocks this, not the comparison itself.
func verifyCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) == 1
}
