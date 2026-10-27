package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// A SHA-256 hash is enough here: the token is 256 bits of random, not a
// guessable password, and every request looks it up by hash.
func HashOpaqueToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// generateOpaqueToken returns the raw token and the hash to persist. Only
// the hash is stored, so a database leak yields no usable tokens.
func generateOpaqueToken() (raw string, hashed string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashOpaqueToken(raw), nil
}
