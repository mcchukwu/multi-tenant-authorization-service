package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// generateOpaqueToken returns a URL-safe random token and its SHA-256 hash
// (hex-encoded) for storage. Hashing before persisting means a leaked
// database doesn't hand out usable tokens directly. The raw token exists
// only in memory and in the one response the client receives it in.
//
// SHA-256, not argon2id, is deliberate here: this token is already 256 bits
// of random entropy, not a low-entropy human password, so there's nothing
// for a slow, memory-hard hash to protect against. A fast hash is correct
// and keeps every authenticated request (which has to look this up) cheap.
func generateOpaqueToken() (raw string, hashed string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	hashed = hex.EncodeToString(sum[:])
	return raw, hashed, nil
}
