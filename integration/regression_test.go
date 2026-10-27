package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerWithoutLastName registers a user with the optional last_name
// omitted. The API accepts this payload, so every read path must handle it.
func registerWithoutLastName(t *testing.T, label string) *testUser {
	t.Helper()

	c := newClient(t)
	email := fmt.Sprintf("%s-%s@example.com", label, uuid.NewString()[:8])
	respBody := expectStatus(t, c, http.MethodPost, "/v1/auth/register", map[string]any{
		"email":      email,
		"password":   testPassword,
		"first_name": label,
	}, http.StatusCreated, nil)

	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var data struct {
		AccessToken string `json:"access_token"`
		User        struct {
			ID string `json:"id"`
		} `json:"user"`
		Organization struct {
			ID string `json:"id"`
		} `json:"organization"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &data))

	c.token = data.AccessToken
	return &testUser{
		client:        c,
		email:         email,
		password:      testPassword,
		accessToken:   data.AccessToken,
		userID:        data.User.ID,
		personalOrgID: data.Organization.ID,
	}
}

// TestAccountsWithoutLastName_CanLoginAndBeListed covers the read side of a
// nullable users.last_name: signing in and appearing in a member list.
func TestAccountsWithoutLastName_CanLoginAndBeListed(t *testing.T) {
	u := registerWithoutLastName(t, "nolast")

	fresh := newClient(t)
	loginOn(t, fresh, u.email, u.password)

	owner := registerUser(t, "nolast-owner")
	orgID := createOrg(t, owner, "No Last Names Ltd")
	inviteAndAccept(t, owner, u, orgID, orgRolesByKind(t, owner, orgID)["member"])

	respBody := expectStatus(t, owner.client, http.MethodGet,
		"/v1/orgs/"+orgID+"/members", nil, http.StatusOK, owner.bearer())

	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var members []struct {
		UserID   string `json:"user_id"`
		LastName string `json:"last_name"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &members))

	found := false
	for _, m := range members {
		if m.UserID == u.userID {
			found = true
			assert.Empty(t, m.LastName, "a missing last_name must serialize as empty, not fail the list")
		}
	}
	require.True(t, found, "the invited member must appear in the org's member list")
}

// TestRefresh_ConcurrentReplayYieldsOneToken fires the same refresh token at
// the API from several goroutines. Rotation must be atomic: exactly one
// request may succeed, and the rest are treated as replay.
func TestRefresh_ConcurrentReplayYieldsOneToken(t *testing.T) {
	u := registerUser(t, "refresh-race")
	refreshValue := u.client.refreshCookie()
	csrfValue := u.client.csrfCookie()
	require.NotEmpty(t, refreshValue)
	require.NotEmpty(t, csrfValue)

	const attempts = 8
	statuses := make([]int, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := range attempts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start

			req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/refresh", nil)
			if err != nil {
				return
			}
			req.Header.Set("X-Forwarded-For", u.client.ip)
			req.Header.Set("X-CSRF-Token", csrfValue)
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshValue, Path: "/v1/auth"})
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfValue, Path: "/v1/auth"})

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			statuses[i] = resp.StatusCode
		}(i)
	}

	close(start)
	wg.Wait()

	ok := 0
	for _, status := range statuses {
		switch status {
		case http.StatusOK:
			ok++
		case http.StatusUnauthorized:
		default:
			t.Fatalf("unexpected refresh status: %v (all: %v)", status, statuses)
		}
	}
	require.Equal(t, 1, ok, "exactly one concurrent refresh may succeed (all: %v)", statuses)
}

func csrfFromBody(t *testing.T, body []byte) string {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	var data struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode csrf_token: %v", err)
	}
	return data.CSRFToken
}

// TestAuthResponsesExposeCSRFToken covers the browser contract: the token is
// returned in the body so a client on another path or origin can echo it.
func TestAuthResponsesExposeCSRFToken(t *testing.T) {
	c := newClient(t)
	email := fmt.Sprintf("csrf-%s@example.com", uuid.NewString()[:8])

	regBody := expectStatus(t, c, http.MethodPost, "/v1/auth/register", map[string]any{
		"email":      email,
		"password":   testPassword,
		"first_name": "Csrf",
		"last_name":  "Body",
	}, http.StatusCreated, nil)
	require.NotEmpty(t, csrfFromBody(t, regBody), "register must return the csrf token in the body")

	fresh := newClient(t)
	loginBody := expectStatus(t, fresh, http.MethodPost, "/v1/auth/login", map[string]any{
		"identifier": email,
		"password":   testPassword,
	}, http.StatusOK, nil)
	require.NotEmpty(t, csrfFromBody(t, loginBody), "login must return the csrf token in the body")

	status, refreshBody := fresh.refresh(t, fresh.csrfCookie())
	require.Equal(t, http.StatusOK, status, "refresh: %s", refreshBody)
	require.NotEmpty(t, csrfFromBody(t, refreshBody), "refresh must return the new csrf token in the body")
}
