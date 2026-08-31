package integration_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRateLimiting_OrgRouteBurst verifies the org limiter's burst behavior
// (NewRateLimiter(5, 10) in production): a fresh org starts with a full
// bucket, so the first 10 requests pass and the 11th onward get 429. An org
// route is used because the IP-keyed login limiter's ~40 ms argon2 cost
// lets the 5/s refill blur the burst boundary mid-test.
func TestRateLimiting_OrgRouteBurst(t *testing.T) {
	owner := registerUser(t, "ratelimit")
	orgID := createOrg(t, owner, "Rate Limited Co")

	const total = 15
	const burst = 10 // mirrors middleware.NewRateLimiter(5, 10) in main.go

	statuses := make([]int, total)
	for i := range total {
		status, header, respBody := owner.client.do(t, http.MethodGet,
			"/v1/orgs/"+orgID+"/roles", nil, nil)
		statuses[i] = status
		if status == http.StatusTooManyRequests {
			assert.Equal(t, "60", header.Get("Retry-After"),
				"429 responses advertise a Retry-After")
		} else {
			assert.Equal(t, http.StatusOK, status,
				"requests inside the burst should reach the handler, got %d: %s", status, respBody)
		}
	}

	// The burst allows exactly 10; the rest are throttled.
	for i := range burst {
		require.NotEqual(t, http.StatusTooManyRequests, statuses[i],
			"request %d (within burst of %d) must NOT be rate-limited", i+1, burst)
	}
	for i := burst; i < total; i++ {
		require.Equal(t, http.StatusTooManyRequests, statuses[i],
			"request %d (past burst of %d) must be rate-limited", i+1, burst)
	}
}

// TestRateLimiting_IsKeyedPerIP proves the auth limiter is keyed per IP
// (via X-Forwarded-For), not global: one client exhausting its bucket
// doesn't affect another. The login route's ~40 ms argon2 cost makes the
// refill non-deterministic mid-hammer, so only the final requests are
// asserted to be throttled.
func TestRateLimiting_IsKeyedPerIP(t *testing.T) {
	// Exhaust the limiter for this specific IP.
	hammer := newClient(t)
	identifier := "hammer-" + uuid.NewString()[:8] + "@example.com"
	const total = 15
	for i := range total {
		status, _, _ := hammer.do(t, http.MethodPost, "/v1/auth/login",
			map[string]any{"identifier": identifier, "password": testPassword}, nil)
		if i >= total-2 {
			require.Equal(t, http.StatusTooManyRequests, status,
				"request %d on the hammer client must be throttled", i+1)
		}
	}

	// A DIFFERENT IP has its own untouched bucket: login still reaches the
	// handler (401 invalid_credentials, not 429).
	c := newClient(t)
	status, _, body := c.do(t, http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": identifier, "password": testPassword}, nil)
	require.Equal(t, http.StatusUnauthorized, status,
		"a different IP must not be rate-limited by another IP's burst (body: %s)", body)
}
