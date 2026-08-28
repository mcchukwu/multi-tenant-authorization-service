package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// newCSRFToken generates a random token for the double-submit cookie
// check. Unlike access/refresh tokens, this is never stored or hashed,
// its only job is to prove the request came from JS that could read the
// cookie, which requires same-origin access. There's nothing to look up
// server-side, so nothing to persist.
func newCSRFToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate csrf token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
