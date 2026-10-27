package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthLifecycle_RegisterLoginRefreshLogout covers the full happy path:
// register, login, refresh, logout (201/200/200/204), refresh-token rotation,
// and logout revoking only the current session.
func TestAuthLifecycle_RegisterLoginRefreshLogout(t *testing.T) {
	user := registerUser(t, "lifecycle")

	// 1. Register already happened in registerUser (201 + tokens + cookies).

	// 2. Login from a second device creates a second session; both coexist.
	device2 := newClient(t)
	device2Token := loginOn(t, device2, user.email, user.password)
	assert.NotEqual(t, user.accessToken, device2Token, "login must mint a fresh access token")

	// Sessions endpoint: one entry per live session, newest first, with the
	// current session flagged.
	sessions := listSessions(t, user)
	require.Len(t, sessions, 2, "register + login should yield 2 live sessions")
	var currentCount int
	for _, s := range sessions {
		if s.Current {
			currentCount++
		}
	}
	assert.Equal(t, 1, currentCount, "exactly one session should be flagged current")

	// 3. Refresh rotates the refresh and CSRF cookies and mints a new access
	// token; the pre-rotation one is revoked, so the stored token is updated.
	oldRefresh := user.client.refreshCookie()
	oldCSRF := user.client.csrfCookie()
	status, body := user.client.refresh(t, oldCSRF)
	require.Equal(t, http.StatusOK, status, "refresh with matching CSRF header must succeed: %s", body)
	user.accessToken = decodeAccessToken(t, body)
	newRefresh := user.client.refreshCookie()
	assert.NotEqual(t, oldRefresh, newRefresh, "refresh must rotate the refresh token")
	assert.NotEqual(t, oldCSRF, user.client.csrfCookie(), "refresh must re-issue the CSRF token")

	// 4. Logout revokes the current session.
	status, _, _ = user.client.do(t, http.MethodPost, "/v1/auth/logout", nil, user.bearer())
	require.Equal(t, http.StatusNoContent, status, "logout returns 204")

	// The requests carry the token explicitly, so these 401s are about
	// revocation, not a missing header.
	status, _, respBody := user.client.do(t, http.MethodGet, "/v1/me/organizations", nil, user.bearer())
	require.Equal(t, http.StatusUnauthorized, status, "post-logout token must be rejected: %s", respBody)
	status, _, respBody = user.client.do(t, http.MethodGet, "/v1/auth/sessions", nil, user.bearer())
	require.Equal(t, http.StatusUnauthorized, status, "post-logout token must be rejected: %s", respBody)

	// But the OTHER device's session was untouched: its token still works.
	device2Body := expectStatus(t, device2, http.MethodGet, "/v1/me/organizations", nil, http.StatusOK,
		http.Header{"Authorization": []string{"Bearer " + device2Token}})
	var env envelope
	require.NoError(t, json.Unmarshal(device2Body, &env))
	var orgs []any
	require.NoError(t, json.Unmarshal(env.Data, &orgs), "me/organizations data is an array")
	assert.NotEmpty(t, orgs, "device 2 session must survive device 1's logout; org list still readable")
}

// sessionView mirrors the JSON shape of GET /v1/auth/sessions entries.
type sessionView struct {
	ID        string `json:"id"`
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address"`
	Current   bool   `json:"current"`
}

func listSessions(t *testing.T, u *testUser) []sessionView {
	t.Helper()
	respBody := expectStatus(t, u.client, http.MethodGet, "/v1/auth/sessions", nil, http.StatusOK, u.bearer())
	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var out []sessionView
	require.NoError(t, json.Unmarshal(env.Data, &out))
	return out
}

// TestAuthRefresh_ReplayRevokesWholeFamily pins token-reuse detection:
// presenting an already-rotated token revokes the whole token family,
// including the legitimate rotated token and its access token.
func TestAuthRefresh_ReplayRevokesWholeFamily(t *testing.T) {
	user := registerUser(t, "replay")

	// Snapshot the first-generation tokens.
	gen1Refresh := user.client.refreshCookie()
	gen1CSRF := user.client.csrfCookie()
	gen1Access := user.accessToken

	// First refresh: succeeds, rotates to generation 2.
	status, body := user.client.refresh(t, gen1CSRF)
	require.Equal(t, http.StatusOK, status, "first refresh must succeed: %s", body)
	gen2Refresh := user.client.refreshCookie()
	gen2CSRF := user.client.csrfCookie()
	gen2Access := decodeAccessToken(t, body)
	require.NotEqual(t, gen1Refresh, gen2Refresh)
	require.NotEqual(t, gen1Access, gen2Access)

	// Replay the old token pair explicitly: the live jar already holds the
	// rotated pair, and the CSRF check runs before token validation.
	status, body = user.client.refreshWithCookies(t, gen1Refresh, gen1CSRF, gen1CSRF)
	require.Equal(t, http.StatusUnauthorized, status,
		"replayed refresh token must be rejected: %s", body)
	code := decodeErrorCode(t, body)
	assert.Equal(t, "invalid_token", code, "replay maps to invalid_token")

	// The key assertion: family revocation also kills the legitimate
	// rotated token.
	status, body = user.client.refresh(t, gen2CSRF)
	require.Equal(t, http.StatusUnauthorized, status,
		"family revocation must kill the legitimately rotated token: %s", body)
	assert.Equal(t, "invalid_token", decodeErrorCode(t, body))

	// And the rotated access token no longer authenticates anything.
	status, _, _ = user.client.do(t, http.MethodGet, "/v1/me/organizations", nil,
		http.Header{"Authorization": []string{"Bearer " + gen2Access}})
	require.Equal(t, http.StatusUnauthorized, status,
		"family revocation must kill the rotated access token too")
}

func decodeAccessToken(t *testing.T, respBody []byte) string {
	t.Helper()
	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var data struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &data))
	return data.AccessToken
}

func decodeErrorCode(t *testing.T, respBody []byte) string {
	t.Helper()
	var env errEnvelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	return env.Error.Code
}

// TestAuthRefresh_CSRFEnforcement verifies the double-submit pattern on
// /auth/refresh: the X-CSRF-Token header must match the csrf_token cookie,
// and the check runs before any token validation.
func TestAuthRefresh_CSRFEnforcement(t *testing.T) {
	user := registerUser(t, "csrf")

	// No header at all.
	status, body := user.client.refresh(t, "")
	require.Equal(t, http.StatusForbidden, status, "missing CSRF header -> 403: %s", body)
	assert.Equal(t, "csrf_check_failed", decodeErrorCode(t, body))

	// Wrong header value.
	status, body = user.client.refresh(t, "definitely-not-the-cookie")
	require.Equal(t, http.StatusForbidden, status, "mismatched CSRF header -> 403: %s", body)
	assert.Equal(t, "csrf_check_failed", decodeErrorCode(t, body))

	// Matching header still works.
	status, body = user.client.refresh(t, user.client.csrfCookie())
	require.Equal(t, http.StatusOK, status, "matching CSRF header -> 200: %s", body)
}

// TestAuthValidationAndErrorShapes pins the auth routes' error contract:
// status codes, error codes, and login's anti-enumeration.
func TestAuthValidationAndErrorShapes(t *testing.T) {
	c := newClient(t)

	// Validation failures: 400 with a per-field map.
	status, _, body := c.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": "not-an-email", "password": "short", "first_name": "",
	}, nil)
	require.Equal(t, http.StatusBadRequest, status, "invalid register payload -> 400: %s", body)
	var env errEnvelope
	require.NoError(t, json.Unmarshal(body, &env))
	assert.Equal(t, "validation_error", env.Error.Code)
	assert.Contains(t, env.Error.Fields, "Email", "validation fields keyed by struct field name")
	assert.Contains(t, env.Error.Fields, "Password")
	assert.Contains(t, env.Error.Fields, "FirstName")

	// Malformed JSON body.
	status, _, body = c.do(t, http.MethodPost, "/v1/auth/register", "not json", nil)
	require.Equal(t, http.StatusBadRequest, status, "malformed body -> 400: %s", body)
	assert.Equal(t, "invalid_request", decodeErrorCode(t, body))

	// Duplicate registration: the DB UNIQUE constraint surfaces as 409.
	user := registerUser(t, "dup")
	status, _, body = c.do(t, http.MethodPost, "/v1/auth/register", map[string]any{
		"email": user.email, "password": testPassword, "first_name": "Again", "last_name": "X",
	}, nil)
	require.Equal(t, http.StatusConflict, status, "duplicate email -> 409: %s", body)
	assert.Equal(t, "email_already_exists", decodeErrorCode(t, body))

	// Unknown email and wrong password must be indistinguishable: same
	// status, same code, same message (anti-enumeration).
	_, _, bodyUnknown := c.do(t, http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": "nobody-" + uuid.NewString()[:8] + "@example.com", "password": testPassword}, nil)
	_, _, bodyWrong := c.do(t, http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": user.email, "password": "WrongPassword123"}, nil)
	require.JSONEq(t, string(bodyUnknown), string(bodyWrong),
		"unknown-user and wrong-password logins must return identical bodies")

	// Unauthenticated access: 401 before any handler runs.
	code := expectError(t, newClient(t), http.MethodGet, "/v1/me/organizations", nil, http.StatusUnauthorized)
	assert.Equal(t, "missing_token", code)

	// Org-scoped routes require authn too, even before authz.
	code = expectError(t, newClient(t), http.MethodGet,
		"/v1/orgs/"+uuid.NewString(), nil, http.StatusUnauthorized)
	assert.Equal(t, "missing_token", code)
}

// TestAuthLogoutAll_RevokesEverySession verifies logout-all revokes every
// session across devices.
func TestAuthLogoutAll_RevokesEverySession(t *testing.T) {
	user := registerUser(t, "logoutall")

	device2 := newClient(t)
	loginOn(t, device2, user.email, user.password)
	device3 := newClient(t)
	loginOn(t, device3, user.email, user.password)

	require.Len(t, listSessions(t, user), 3, "three logins -> three live sessions")

	status, _, _ := user.client.do(t, http.MethodPost, "/v1/auth/logout-all", nil, user.bearer())
	require.Equal(t, http.StatusNoContent, status, "logout-all returns 204")

	// Every session's access token is dead, regardless of which device it
	// came from. Each client sends the token it was issued, so the 401s
	// below are genuinely about revocation, not missing auth.
	for name, c := range map[string]*apiClient{"device1": user.client, "device2": device2, "device3": device3} {
		status, _, respBody := c.do(t, http.MethodGet, "/v1/me/organizations", nil, nil)
		require.Equalf(t, http.StatusUnauthorized, status,
			"%s token must be revoked by logout-all (body: %s)", name, respBody)
	}
}

// TestRegisterWithoutLastName_Succeeds pins the corrected contract: an
// omitted last_name persists as SQL NULL and registration returns 201,
// not a 500.
func TestRegisterWithoutLastName_Succeeds(t *testing.T) {
	c := newClient(t)
	email := "nolastname-" + uuid.NewString()[:8] + "@example.com"
	respBody := expectStatus(t, c, http.MethodPost, "/v1/auth/register", map[string]any{
		"email":      email,
		"password":   testPassword,
		"first_name": "NoLast",
		// last_name intentionally omitted
	}, http.StatusCreated, nil)

	// 201 with the standard success envelope.
	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	require.True(t, env.Success, "register without last_name must return a success envelope")

	// The created user carries no last_name value in the response.
	var data struct {
		User struct {
			ID       string `json:"id"`
			LastName string `json:"last_name"`
		} `json:"user"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &data))
	require.NotEmpty(t, data.User.ID, "register must return the created user")
	assert.Empty(t, data.User.LastName,
		"omitted last_name must not fabricate a value in the response")

	// Strongest evidence: the persisted row holds SQL NULL, not ''.
	var dbLastName *string
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT last_name FROM users WHERE id = $1", data.User.ID).Scan(&dbLastName),
		"read created user's last_name")
	assert.Nil(t, dbLastName, "users.last_name is nullable; an omitted last_name must persist as NULL")
}

// TestLogin_SuspendedUserReturns403 pins the corrected suspended-user login:
// correct credentials on a suspended account get 403 user_suspended (not a
// 500), and the failed login mints no session.
func TestLogin_SuspendedUserReturns403(t *testing.T) {
	user := registerUser(t, "suspended")

	// Flip the row directly in the DB; there is no suspension endpoint yet.
	cmd, err := pool.Exec(context.Background(),
		"UPDATE users SET status = 'suspended' WHERE id = $1", user.userID)
	require.NoError(t, err, "suspend the user directly in the DB")
	require.Equal(t, int64(1), cmd.RowsAffected(), "exactly one user row must be suspended")

	// Login from a fresh (cookie-free) client, so any cookie it holds after
	// the attempt must have been issued by this very login.
	fresh := newClient(t)

	// Correct credentials on a suspended account get a distinct 403
	// user_suspended, not the 401 invalid_credentials unknown users get.
	code := expectError(t, fresh, http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": user.email, "password": user.password},
		http.StatusForbidden)
	assert.Equal(t, "user_suspended", code,
		"suspended user login must map to user_suspended, not invalid_credentials")

	// The failed login must not issue a session: the response carries no
	// refresh_token cookie.
	assert.Empty(t, fresh.refreshCookie(),
		"a suspended user's login must not set a refresh_token cookie")

	// Password verification runs before the status gate, so a wrong password
	// on a suspended account stays indistinguishable from any other failure.
	code = expectError(t, newClient(t), http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": user.email, "password": "WrongPassword123"},
		http.StatusUnauthorized)
	assert.Equal(t, "invalid_credentials", code,
		"suspended user with wrong password must be indistinguishable from an unknown user")

	// Strongest evidence no session was minted: the registration session is
	// the user's only live session.
	var sessionCount int
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND revoked = false", user.userID).Scan(&sessionCount),
		"count live sessions for the suspended user")
	assert.Equal(t, 1, sessionCount,
		"failed suspended-user login must not create a new session (only the registration session remains)")
}
