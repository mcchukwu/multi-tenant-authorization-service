package auth

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHashOpaqueToken_Deterministic pins the token-hashing contract (SHA-256
// hex, 64 lowercase chars, deterministic). Determinism is load-bearing:
// sessions are looked up by hash, so the same raw token must always hash
// the same.
func TestHashOpaqueToken_Deterministic(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"short", "abc"},
		{"token-shaped", "aB3_xY9-0qWz1mNopQrStUvWxYz1234567890"},
		{"long", strings.Repeat("t", 1000)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := HashOpaqueToken(tc.input)
			second := HashOpaqueToken(tc.input)

			assert.Equal(t, first, second, "same input must always hash identically")
			assert.Len(t, first, 64, "SHA-256 hex digest is exactly 64 characters")
			if _, err := hex.DecodeString(first); err != nil {
				t.Fatalf("output %q is not valid hex: %v", first, err)
			}
		})
	}

	// Different inputs must differ; a degenerate hash would make every
	// user's token interchangeable (session confusion).
	assert.NotEqual(t, HashOpaqueToken("token-a"), HashOpaqueToken("token-b"),
		"distinct inputs must hash to distinct values")
}

// TestGenerateOpaqueToken checks shape and uniqueness of generated tokens:
// raw != hashed, hashed == HashOpaqueToken(raw) (otherwise lookups could
// never match), no collisions across 10,000 draws, and the expected lengths
// (43 URL-safe base64 chars raw, 64 hex chars hashed).
func TestGenerateOpaqueToken(t *testing.T) {
	const draws = 10_000

	raws := make(map[string]struct{}, draws)
	hashes := make(map[string]struct{}, draws)

	for i := range draws {
		raw, hashed, err := generateOpaqueToken()
		require.NoError(t, err, "token generation at draw %d", i)

		require.NotEqual(t, raw, hashed, "raw token must never equal its hash (draw %d)", i)
		require.Equal(t, HashOpaqueToken(raw), hashed,
			"generated hash must be the public HashOpaqueToken of the raw value (draw %d)", i)
		require.Len(t, raw, 43, "raw token is 32 random bytes in unpadded URL-safe base64 (draw %d)", i)
		require.Len(t, hashed, 64, "hashed token is the hex SHA-256 (draw %d)", i)

		if _, dup := raws[raw]; dup {
			t.Fatalf("raw token collision at draw %d: %q was already generated", i, raw)
		}
		if _, dup := hashes[hashed]; dup {
			t.Fatalf("hashed token collision at draw %d: %q was already generated", i, hashed)
		}
		raws[raw] = struct{}{}
		hashes[hashed] = struct{}{}
	}

	assert.Len(t, raws, draws, "all %d raw tokens must be unique", draws)
	assert.Len(t, hashes, draws, "all %d hashes must be unique", draws)
}
