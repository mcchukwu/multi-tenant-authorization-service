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

// setAuthCookies always sets both cookies together.
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
		HttpOnly: false, // It's echoed back in a header, not a secret credential on its own
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
	})
}

// MaxAge -1 deletes the cookies now instead of waiting for expiry.
func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     authCookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     authCookiePath,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// verifyCSRF is a double-submit check: a cross-site attacker can send the
// cookie but cannot read it to set the matching header.
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
