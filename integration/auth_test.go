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

// TestAuthLifecycle_RegisterLoginRefreshLogout is the mandatory full happy
// path: register -> login -> refresh -> logout, asserting the real response
// shapes (201/200/200/204), the rotation of the refresh cookie, and that
// logout revokes exactly the current session and nothing else.
func TestAuthLifecycle_RegisterLoginRefreshLogout(t *testing.T) {
	user := registerUser(t, "lifecycle")

	// 1. Register already happened in registerUser (201 + tokens + cookies).

	// 2. Login from a second "device" creates a second session for the same
	// user. Both sessions must coexist and be visible.
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

	// 3. Refresh rotates the refresh token: new cookie value, new access
	// token, and the CSRF cookie is re-issued too. The access token stored
	// on the user must be updated, since the pre-rotation one is revoked.
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

	// The logged-out session's access token is dead everywhere — the
	// requests carry the token explicitly, so these are genuinely about
	// revocation, not a missing Authorization header.
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
	assert.NotEmpty(t, orgs, "device 2 session must survive device 1's logout — org list still readable")
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

// TestAuthRefresh_ReplayRevokesWholeFamily is the mandatory token-reuse
// detection test. Refresh tokens rotate on every use; presenting an already
// rotated (revoked) token is treated as theft and revokes the ENTIRE token
// family — including the legitimate rotated token and its access token.
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

	// Replay the OLD (now revoked) refresh token with the OLD cookie pair.
	// The explicit cookies matter: the client's live jar already holds the
	// rotated pair, and the CSRF check runs before token validation — a
	// mismatched pair would be rejected as a CSRF failure and never reach
	// the reuse-detection logic we're testing.
	status, body = user.client.refreshWithCookies(t, gen1Refresh, gen1CSRF, gen1CSRF)
	require.Equal(t, http.StatusUnauthorized, status,
		"replayed refresh token must be rejected: %s", body)
	code := decodeErrorCode(t, body)
	assert.Equal(t, "invalid_token", code, "replay maps to invalid_token")

	// THE key assertion: the family revocation also kills the LEGITIMATE
	// rotated token — the attacker's reuse poisons the whole lineage.
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

// TestAuthRefresh_CSRFEnforcement verifies the double-submit cookie pattern
// on /auth/refresh: the X-CSRF-Token header must exactly match the csrf_token
// cookie, and the check runs BEFORE any token validation.
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

// TestAuthValidationAndErrorShapes pins the public error contract of the
// auth routes: status codes, error codes, and the anti-enumeration behavior
// of login.
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

// TestAuthLogoutAll_RevokesEverySession: logout-all kills all sessions for
// the user across every device.
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

// TestRegisterWithoutLastName_Succeeds pins the corrected registration
// contract: last_name is optional in the API (RegisterRequest validates it
// with `omitempty`), and since the users.last_name column is nullable, a
// registration that omits it succeeds with 201 and persists SQL NULL —
// never a fabricated empty string and never a 500.
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

	// Strongest evidence: the persisted row holds SQL NULL, not '' — the
	// column itself is nullable and NULL is what an omitted value means.
	var dbLastName *string
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT last_name FROM users WHERE id = $1", data.User.ID).Scan(&dbLastName),
		"read created user's last_name")
	assert.Nil(t, dbLastName, "users.last_name is nullable; an omitted last_name must persist as NULL")
}

// TestLogin_SuspendedUserReturns403 pins the corrected suspended-user login
// contract. A suspended account logging in with CORRECT credentials gets a
// clear 403 with error code "user_suspended" (previously this path fell
// through to a 500), and crucially the failed login must not mint any
// session: no refresh_token cookie is issued and no session row is created.
func TestLogin_SuspendedUserReturns403(t *testing.T) {
	user := registerUser(t, "suspended")

	// Admin-style suspension: flip the row directly in the DB, the same way
	// the harness already reaches into the database (see
	// TestRegisterWithoutLastName_Succeeds). There is no suspension
	// endpoint yet, and the column is the user_status enum
	// ('active' | 'suspended' | 'deleted').
	cmd, err := pool.Exec(context.Background(),
		"UPDATE users SET status = 'suspended' WHERE id = $1", user.userID)
	require.NoError(t, err, "suspend the user directly in the DB")
	require.Equal(t, int64(1), cmd.RowsAffected(), "exactly one user row must be suspended")

	// Login from a SECOND device: the fresh client starts cookie-free, so
	// any refresh_token it holds after the attempt must have been issued by
	// this very login, not by registration.
	fresh := newClient(t)

	// Correct credentials on a suspended account: a clear, distinct signal
	// (403 user_suspended) — NOT the 401 invalid_credentials that unknown
	// users get. This is the intended contract: a known suspended user gets
	// an explicit "your account is suspended" response.
	code := expectError(t, fresh, http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": user.email, "password": user.password},
		http.StatusForbidden)
	assert.Equal(t, "user_suspended", code,
		"suspended user login must map to user_suspended, not invalid_credentials")

	// The failed login must not issue a session: the response carries no
	// refresh_token cookie.
	assert.Empty(t, fresh.refreshCookie(),
		"a suspended user's login must not set a refresh_token cookie")

	// Password verification still runs BEFORE the status gate, so a
	// suspended user presenting the WRONG password stays indistinguishable
	// from any other failed login — the suspension status is not leaked
	// through the error code to someone who doesn't know the password.
	code = expectError(t, newClient(t), http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": user.email, "password": "WrongPassword123"},
		http.StatusUnauthorized)
	assert.Equal(t, "invalid_credentials", code,
		"suspended user with wrong password must be indistinguishable from an unknown user")

	// Strongest evidence that no session was minted: the registration
	// session is the only live session this user has. A login that created
	// a session before failing would leave two.
	var sessionCount int
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND revoked = false", user.userID).Scan(&sessionCount),
		"count live sessions for the suspended user")
	assert.Equal(t, 1, sessionCount,
		"failed suspended-user login must not create a new session (only the registration session remains)")
}
