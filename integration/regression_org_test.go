package integration_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeletedOrganization_IsClosedToMembers verifies that soft delete is a
// terminal state: members lose access and pending invitations cannot be
// redeemed afterwards.
func TestDeletedOrganization_IsClosedToMembers(t *testing.T) {
	f := seedOrg(t, "deleted")
	invitee := registerUser(t, "deleted-invitee")

	// Mint an invitation before the org is deleted.
	roles := orgRolesByKind(t, f.Owner, f.OrgID)
	inviteBody := expectStatus(t, f.Owner.client, http.MethodPost,
		"/v1/orgs/"+f.OrgID+"/members/invite",
		map[string]any{"role_id": roles["viewer"]}, http.StatusCreated, f.Owner.bearer())
	var inviteEnv envelope
	require.NoError(t, json.Unmarshal(inviteBody, &inviteEnv))
	var invite struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(inviteEnv.Data, &invite))

	expectStatus(t, f.Owner.client, http.MethodDelete,
		"/v1/orgs/"+f.OrgID, nil, http.StatusNoContent, f.Owner.bearer())

	// The authorization gate runs first, so the org's own owner is treated
	// like any other non-member from here on.
	expectError(t, f.Owner.client, http.MethodGet,
		"/v1/orgs/"+f.OrgID, nil, http.StatusForbidden)
	expectError(t, f.Owner.client, http.MethodGet,
		"/v1/orgs/"+f.OrgID+"/members", nil, http.StatusForbidden)
	expectError(t, f.Owner.client, http.MethodGet,
		"/v1/orgs/"+f.OrgID+"/roles", nil, http.StatusForbidden)
	expectError(t, f.Owner.client, http.MethodGet,
		"/v1/orgs/"+f.OrgID+"/audit-logs", nil, http.StatusForbidden)
	expectError(t, f.Owner.client, http.MethodPatch,
		"/v1/orgs/"+f.OrgID, map[string]any{"name": "Zombie Org"}, http.StatusForbidden)

	orgList := expectStatus(t, f.Owner.client, http.MethodGet,
		"/v1/me/organizations", nil, http.StatusOK, f.Owner.bearer())
	assert.NotContains(t, string(orgList), f.OrgID,
		"a deleted org must not appear in the caller's org list")

	// Leaving is the one member route without a permission check, so it
	// needs its own guard.
	expectError(t, f.Member.client, http.MethodPost,
		"/v1/orgs/"+f.OrgID+"/leave", nil, http.StatusNotFound)

	// The pre-deletion invitation is dead.
	expectError(t, invitee.client, http.MethodPost,
		"/v1/auth/invitations/"+invite.Token+"/accept", nil, http.StatusUnauthorized)
}
