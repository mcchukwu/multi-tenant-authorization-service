package integration_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRateLimiting_OrgRouteBurst is the mandatory rate-limit test.
//
// Production constructs limiters as NewRateLimiter(5, 10) — 10 tokens of
// burst, refilling at 5 tokens/second (see internal/middleware/ratelimit.go
// and cmd/main.go). The org-scoped limiter keys on the {org_id} path value,
// and this test uses a freshly created org, so its bucket starts full and
// the test is deterministic: the first 10 requests pass, the 11th onward
// must be rejected with 429.
//
// Why an org route and not POST /auth/login: the login limiter is keyed by
// IP and each login attempt costs ~40 ms of argon2 verification, so 15
// requests span ~600 ms — enough for the 5/s refill to add tokens mid-test
// and blur the burst boundary. The org route's authn+authz+list round trip
// completes in ~2 ms, so 15 requests finish in tens of milliseconds, far
// faster than the 200 ms per token refill — the strict pattern holds.
func TestRateLimiting_OrgRouteBurst(t *testing.T) {
	owner := registerUser(t, "ratelimit")
	orgID := createOrg(t, owner, "Rate Limited Co")

	const total = 15
	const burst = 10 // mirrors middleware.NewRateLimiter(5, 10) in main.go

	statuses := make([]int, total)
	for i := 0; i < total; i++ {
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
	for i := 0; i < burst; i++ {
		require.NotEqual(t, http.StatusTooManyRequests, statuses[i],
			"request %d (within burst of %d) must NOT be rate-limited", i+1, burst)
	}
	for i := burst; i < total; i++ {
		require.Equal(t, http.StatusTooManyRequests, statuses[i],
			"request %d (past burst of %d) must be rate-limited", i+1, burst)
	}
}

// TestRateLimiting_IsKeyedPerIP proves the auth limiter is keyed by client
// IP (via X-Forwarded-For), not global: one client exhausting its bucket
// must not affect another client's bucket. The login route is deliberately
// used here because hammering it also documents the refill behavior: each
// attempt costs ~40 ms of argon2 verification, so the 5/s refill can add a
// couple of tokens mid-hammer — the assertions therefore only require the
// FINAL requests to be throttled, which is the robust invariant.
func TestRateLimiting_IsKeyedPerIP(t *testing.T) {
	// Exhaust the limiter for this specific IP.
	hammer := newClient(t)
	identifier := "hammer-" + uuid.NewString()[:8] + "@example.com"
	const total = 15
	for i := 0; i < total; i++ {
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
