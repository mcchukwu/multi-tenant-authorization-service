package auth_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// TestHashPasswordVerifyPassword_RoundTrip pins the core password contract:
// HashPassword produces an argon2id PHC string that VerifyPassword accepts
// for the same password and rejects for any other password.
//
// The expected values here are independent of the implementation: we assert
// the PHC prefix literally (the stored-hash format is a cross-cutting
// contract — it's what the DB column holds and what login re-derives from),
// and correctness of the match/mismatch outcomes, never a recomputation of
// the hash itself.
func TestHashPasswordVerifyPassword_RoundTrip(t *testing.T) {
	passwords := []string{
		"correct horse battery staple",
		"p@ssW0rd!123",
		"a", // no minimum enforced here; min-length lives in request validation
		"пароль🔐",
		strings.Repeat("x", 72),
		"",
	}

	for _, pw := range passwords {
		t.Run(fmt.Sprintf("password %q", pw), func(t *testing.T) {
			hash, err := auth.HashPassword(pw)
			require.NoError(t, err, "HashPassword must never fail for a valid input")
			require.NotEmpty(t, hash)

			// The PHC shape is part of the storage contract — the DB stores
			// this exact prefix and VerifyPassword parses it back.
			assert.True(t,
				strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$"),
				"hash should be an argon2id PHC string with the production params, got %q", hash,
			)

			ok, err := auth.VerifyPassword(hash, pw)
			require.NoError(t, err)
			assert.True(t, ok, "correct password must verify")

			ok, err = auth.VerifyPassword(hash, pw+"-definitely-wrong")
			require.NoError(t, err)
			assert.False(t, ok, "wrong password must not verify")
		})
	}
}

// TestVerifyPassword_RejectsMalformedHashes ensures a corrupt or hostile
// stored hash cannot panic, error in a confusing way, or be accepted.
// Every case must return an error and must not return ok=true.
func TestVerifyPassword_RejectsMalformedHashes(t *testing.T) {
	cases := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"plain text, not PHC", "just a plain string"},
		{"too few segments", "$argon2id$v=19$abc"},
		{"wrong algorithm", "$bcrypt$v=2a$12$c2hQqM9zU8nXzY1aBcDeF$abcdefghijklmnopqrstuvwxyz012345"},
		{"version not a number", "$argon2id$v=notanumber$m=19456,t=2,p=1$AAAA$AAAA"},
		{"params not numbers", "$argon2id$v=19$m=bad,t=2,p=1$AAAA$AAAA"},
		{"salt not base64", "$argon2id$v=19$m=19456,t=2,p=1$@@@$AAAA"},
		{"hash not base64", "$argon2id$v=19$m=19456,t=2,p=1$AAAA$@@@"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := auth.VerifyPassword(tc.hash, "any-password")
			require.Error(t, err, "malformed hash %q must return an error", tc.hash)
			assert.False(t, ok, "malformed hash %q must never verify as true", tc.hash)
		})
	}
}

// TestVerifyPassword_HonorsParamsEmbeddedInHash is the anti-tautology test
// for the parameter-parsing path. VerifyPassword claims to re-derive using
// the parameters embedded in the hash (m/t/p), NOT the package constants
// (m=19456,t=2,p=1). We prove that by building a valid PHC string with
// deliberately DIFFERENT parameters (m=65536,t=3,p=2), computed with
// argon2.IDKey directly in the test, and asserting VerifyPassword accepts
// it. If the implementation ignored the embedded params and re-used today's
// constants, this test would fail — and if it recomputed expectations the
// way the code does, it would pass by construction.
func TestVerifyPassword_HonorsParamsEmbeddedInHash(t *testing.T) {
	const (
		memory     = 64 * 1024 // 64 MiB — deliberately different from production's 19 MiB
		iterations = 3         // production uses 2
		keyLen     = 32
	)
	var parallelism uint8 = 2 // production uses 1

	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	digest := argon2.IDKey([]byte("a-different-secret"), salt, iterations, memory, parallelism, keyLen)
	phc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory,
		iterations,
		parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)

	ok, err := auth.VerifyPassword(phc, "a-different-secret")
	require.NoError(t, err)
	assert.True(t, ok, "hash minted with non-default params must verify via its embedded params")

	ok, err = auth.VerifyPassword(phc, "wrong-secret")
	require.NoError(t, err)
	assert.False(t, ok)
}
