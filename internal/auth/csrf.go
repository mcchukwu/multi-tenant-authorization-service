package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// newCSRFToken is not stored: the double-submit check only compares the
// cookie with the request header.
func newCSRFToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate csrf token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
