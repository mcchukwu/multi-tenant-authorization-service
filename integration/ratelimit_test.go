package integration_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/middleware"
)

// TestRateLimiting_OrgRouteBurst checks the org limiter's burst boundary.
// The limiter refills at zero here so the boundary cannot drift with the
// wall clock while the requests are in flight.
func TestRateLimiting_OrgRouteBurst(t *testing.T) {
	owner := registerUser(t, "ratelimit")
	orgID := createOrg(t, owner, "Rate Limited Co")

	srv := buildServerWithLimiters(pool, appConfig,
		middleware.NewRateLimiter(1000, 1000),
		middleware.NewRateLimiter(0, 10),
	)
	defer srv.Close()
	owner.client.base = srv.URL

	const (
		total = 12
		burst = 10
	)

	for i := range total {
		status, header, body := owner.client.do(t, http.MethodGet,
			"/v1/orgs/"+orgID+"/roles", nil, nil)

		if i < burst {
			require.NotEqual(t, http.StatusTooManyRequests, status,
				"request %d must fit in the burst (body: %s)", i+1, body)
			continue
		}

		require.Equal(t, http.StatusTooManyRequests, status,
			"request %d must be throttled (body: %s)", i+1, body)
		assert.Equal(t, "60", header.Get("Retry-After"), "429 responses advertise Retry-After")
	}
}

// TestRateLimiting_IsKeyedPerIP proves the auth limiter is keyed on the
// client IP: one exhausted bucket must not affect another address.
func TestRateLimiting_IsKeyedPerIP(t *testing.T) {
	srv := buildServerWithLimiters(pool, appConfig,
		middleware.NewRateLimiter(0, 3),
		middleware.NewRateLimiter(1000, 1000),
	)
	defer srv.Close()

	identifier := "hammer-" + uuid.NewString()[:8] + "@example.com"
	hammer := newClientAt(t, srv.URL)

	for i := range 3 {
		status, _, body := hammer.do(t, http.MethodPost, "/v1/auth/login",
			map[string]any{"identifier": identifier, "password": testPassword}, nil)
		require.Equal(t, http.StatusUnauthorized, status,
			"request %d should reach the handler (body: %s)", i+1, body)
	}

	status, _, body := hammer.do(t, http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": identifier, "password": testPassword}, nil)
	require.Equal(t, http.StatusTooManyRequests, status,
		"request past the burst must be throttled (body: %s)", body)

	other := newClientAt(t, srv.URL)
	status, _, body = other.do(t, http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": identifier, "password": testPassword}, nil)
	require.Equal(t, http.StatusUnauthorized, status,
		"a different IP must have its own bucket (body: %s)", body)
}
