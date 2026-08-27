package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 19 * 1024 // KiB
	argonIterations  = 2
	argonParallelism = 1
	argonSaltLength  = 16
	argonKeyLength   = 32
)

// HashPassword returns an encoded argon2id hash in PHC string format:
// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

// VerifyPassword re-derives a hash from the candidate password using the
// parameters embedded in the stored hash (not today's constants), then
// compares in constant time. Re-reading the stored parameters means a
// future change to argonMemory/argonIterations doesn't break verification
// of passwords hashed under the old settings.
func VerifyPassword(encodedHash, password string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("parse version: %w", err)
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, fmt.Errorf("parse params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	candidateHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(storedHash)))

	// Constant-time comparison — a short-circuiting comparison here would
	// leak how many leading bytes matched via response timing, defeating
	// the point of hashing the password in the first place.
	return subtle.ConstantTimeCompare(storedHash, candidateHash) == 1, nil
}

// dummyHash is a valid argon2id hash of an unrelated random password,
// computed once at startup. Used to keep login response timing constant
// when the looked-up user doesn't exist — see Service.Login. Computed via
// HashPassword rather than hardcoded, so it's always correctly formed and
// costs exactly the same as a real hash to verify against.
var dummyHash string

func init() {
	h, err := HashPassword("correct-horse-battery-staple-dummy-seed")
	if err != nil {
		panic("auth: failed to precompute dummy hash: " + err.Error())
	}
	dummyHash = h
}
