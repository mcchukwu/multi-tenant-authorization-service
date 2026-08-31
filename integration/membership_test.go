package integration_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memberView mirrors the JSON shape of GET /v1/orgs/{id}/members entries.
type memberView struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	RoleName string `json:"role_name"`
	RoleKind string `json:"role_kind"`
	Status   string `json:"status"`
}

func listMembers(t *testing.T, actor *testUser, orgID string) []memberView {
	t.Helper()
	respBody := expectStatus(t, actor.client, http.MethodGet,
		"/v1/orgs/"+orgID+"/members", nil, http.StatusOK, actor.bearer())
	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var out []memberView
	require.NoError(t, json.Unmarshal(env.Data, &out))
	return out
}

func memberIDs(members []memberView) map[string]bool {
	out := make(map[string]bool, len(members))
	for _, m := range members {
		out[m.UserID] = true
	}
	return out
}

func countRoleKind(members []memberView, kind string) int {
	n := 0
	for _, m := range members {
		if m.RoleKind == kind {
			n++
		}
	}
	return n
}

// TestViewerRoleRestrictions is the role-matrix test: a viewer can view the
// org but every mutating capability, including member-list visibility, is
// denied at the authz middleware with 403 forbidden.
func TestViewerRoleRestrictions(t *testing.T) {
	fx := seedOrg(t, "viewer")

	// Viewer CAN view the org itself (org.view is granted to viewer).
	decodeData(t, fx.Viewer.client, http.MethodGet, "/v1/orgs/"+fx.OrgID, http.StatusOK)

	// Viewer CANNOT view the member list (viewer lacks member.view).
	code := expectError(t, fx.Viewer.client, http.MethodGet,
		"/v1/orgs/"+fx.OrgID+"/members", nil, http.StatusForbidden)
	assert.Equal(t, "forbidden", code)

	// Viewer CANNOT invite, remove, or assign roles.
	code = expectError(t, fx.Viewer.client, http.MethodPost,
		"/v1/orgs/"+fx.OrgID+"/members/invite",
		map[string]any{"role_id": fx.Roles["member"]}, http.StatusForbidden)
	assert.Equal(t, "forbidden", code, "invite denied at middleware")

	code = expectError(t, fx.Viewer.client, http.MethodDelete,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Member.userID, nil, http.StatusForbidden)
	assert.Equal(t, "forbidden", code, "remove denied at middleware")

	code = expectError(t, fx.Viewer.client, http.MethodPatch,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Member.userID+"/role",
		map[string]any{"role_id": fx.Roles["viewer"]}, http.StatusForbidden)
	assert.Equal(t, "forbidden", code, "assign-role denied at middleware")

	// The authz decision trail must contain the denied invite: every check,
	// allowed or denied, is recorded with its outcome.
	decisions := listDecisions(t, fx.Owner, fx.OrgID)
	foundDeniedInvite := false
	for _, d := range decisions {
		if d.PermissionKey == "member.invite" && d.UserID != nil && *d.UserID == fx.Viewer.userID && !d.Allowed {
			foundDeniedInvite = true
			assert.Contains(t, d.Reason, "lacks permission")
		}
	}
	assert.True(t, foundDeniedInvite,
		"the viewer's denied invite attempt must appear in the authz decision trail")
}

// decisionView mirrors the JSON shape of GET /v1/orgs/{id}/authz-decisions.
type decisionView struct {
	UserID        *string `json:"user_id"`
	PermissionKey string  `json:"permission_key"`
	Allowed       bool    `json:"allowed"`
	Reason        string  `json:"reason"`
}

func listDecisions(t *testing.T, actor *testUser, orgID string) []decisionView {
	t.Helper()
	respBody := expectStatus(t, actor.client, http.MethodGet,
		"/v1/orgs/"+orgID+"/authz-decisions", nil, http.StatusOK, actor.bearer())
	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var out []decisionView
	require.NoError(t, json.Unmarshal(env.Data, &out))
	return out
}

// TestLastOwnerCannotBeRemovedOrDemoted pins the min-one-owner invariant:
// with one owner, remove and self-demote both return 409 last_owner; with a
// co-owner, removing one owner is allowed and the guard returns.
func TestLastOwnerCannotBeRemovedOrDemoted(t *testing.T) {
	fx := seedOrg(t, "lastowner")

	// Sole owner removes themself -> 409 last_owner.
	code := expectError(t, fx.Owner.client, http.MethodDelete,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Owner.userID, nil, http.StatusConflict)
	assert.Equal(t, "last_owner", code)

	// Sole owner demotes themself away from owner -> same guard, 409.
	code = expectError(t, fx.Owner.client, http.MethodPatch,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Owner.userID+"/role",
		map[string]any{"role_id": fx.Roles["member"]}, http.StatusConflict)
	assert.Equal(t, "last_owner", code, "demoting the last owner is as dangerous as removing them")

	// Bring in a co-owner through the real invite+accept flow.
	coowner := registerUser(t, "lastowner-coowner")
	inviteAndAccept(t, fx.Owner, coowner, fx.OrgID, fx.Roles["owner"])
	assert.Equal(t, 2, countRoleKind(listMembers(t, fx.Owner, fx.OrgID), "owner"),
		"two owners after co-owner joins")

	// With two owners, removing one is fine.
	expectStatus(t, fx.Owner.client, http.MethodDelete,
		"/v1/orgs/"+fx.OrgID+"/members/"+coowner.userID, nil, http.StatusNoContent, fx.Owner.bearer())

	// Back to one owner: the invariant is restored.
	code = expectError(t, fx.Owner.client, http.MethodDelete,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Owner.userID, nil, http.StatusConflict)
	assert.Equal(t, "last_owner", code)
}

// TestOwnerActionRestricted pins the owner-privilege guard: an admin can
// manage normal members but never touch anyone's owner status, in either
// direction (403 owner_action_restricted from the service layer).
func TestOwnerActionRestricted(t *testing.T) {
	fx := seedOrg(t, "ownerrestricted")

	// Admin removing the owner: middleware (member.remove) passes, the
	// service layer rejects because only an owner may remove an owner.
	code := expectError(t, fx.Admin.client, http.MethodDelete,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Owner.userID, nil, http.StatusForbidden)
	assert.Equal(t, "owner_action_restricted", code)

	// Admin granting the owner role to a member (promotion).
	code = expectError(t, fx.Admin.client, http.MethodPatch,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Member.userID+"/role",
		map[string]any{"role_id": fx.Roles["owner"]}, http.StatusForbidden)
	assert.Equal(t, "owner_action_restricted", code)

	// Admin inviting someone in as an owner.
	code = expectError(t, fx.Admin.client, http.MethodPost,
		"/v1/orgs/"+fx.OrgID+"/members/invite",
		map[string]any{"role_id": fx.Roles["owner"]}, http.StatusForbidden)
	assert.Equal(t, "owner_action_restricted", code)

	// Sanity: the admin can invite into a non-owner role; the restriction
	// is target-role-specific.
	invitee := registerUser(t, "ownerrestricted-invitee")
	inviteAndAccept(t, fx.Admin, invitee, fx.OrgID, fx.Roles["member"])
	assert.True(t, memberIDs(listMembers(t, fx.Owner, fx.OrgID))[invitee.userID],
		"admin's invite into the member role must succeed")

	// Demoting the owner fires the same guard in the other direction;
	// previously only granting was blocked.
	code = expectError(t, fx.Admin.client, http.MethodPatch,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Owner.userID+"/role",
		map[string]any{"role_id": fx.Roles["member"]}, http.StatusForbidden)
	assert.Equal(t, "owner_action_restricted", code)
}

// TestOwnerAssignRole_NonOwnerTargetIsAllowed: the owner guard is about
// owner status specifically; reassigning a non-owner member's role is fine.
func TestOwnerAssignRole_NonOwnerTargetIsAllowed(t *testing.T) {
	owner := registerUser(t, "ownergrant")
	admin := registerUser(t, "ownergrant-admin")
	orgID := createOrg(t, owner, "Owner Grant Co")
	roles := orgRolesByKind(t, owner, orgID)
	require.Contains(t, roles, "admin")
	inviteAndAccept(t, owner, admin, orgID, roles["admin"])

	expectStatus(t, owner.client, http.MethodPatch,
		"/v1/orgs/"+orgID+"/members/"+admin.userID+"/role",
		map[string]any{"role_id": roles["viewer"]}, http.StatusNoContent, owner.bearer())

	// The reassignment took effect: the admin now holds the viewer role.
	assert.Equal(t, "viewer", roleKindOf(t, listMembers(t, owner, orgID), admin.userID),
		"owner can reassign a non-owner member's role without tripping the owner-action guard")
}

// TestIDOR_CrossOrgMemberDeleteIs404: the (id, organization_id) scoping
// pattern collapses "member of another org" and "no such member" into the
// same 404.
func TestIDOR_CrossOrgMemberDeleteIs404(t *testing.T) {
	fx := seedOrg(t, "idor")

	// A user who exists but belongs to a different org (their own personal
	// org, unrelated to fx.OrgID).
	outsider := registerUser(t, "idor-outsider")

	code := expectError(t, fx.Owner.client, http.MethodDelete,
		"/v1/orgs/"+fx.OrgID+"/members/"+outsider.userID, nil, http.StatusNotFound)
	assert.Equal(t, "membership_not_found", code,
		"cross-org member delete must look like a plain 404")

	// A random UUID must be indistinguishable: same status, code, message.
	randomID := uuid.NewString()
	codeRandom := expectError(t, fx.Owner.client, http.MethodDelete,
		"/v1/orgs/"+fx.OrgID+"/members/"+randomID, nil, http.StatusNotFound)
	assert.Equal(t, code, codeRandom, "foreign user and nonexistent user must be indistinguishable")

	// Control: a real member of the org is removable, so the 404 above is
	// scope filtering, not a broken delete.
	expectStatus(t, fx.Owner.client, http.MethodDelete,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Member.userID, nil, http.StatusNoContent, fx.Owner.bearer())
}

// TestNonMemberOrgAccess: an org the caller isn't a member of is denied at
// the middleware with 403, identically for a real foreign org and a random
// org ID.
func TestNonMemberOrgAccess(t *testing.T) {
	fx := seedOrg(t, "foreign")
	stranger := registerUser(t, "foreign-stranger")

	// Real org the stranger isn't a member of.
	code := expectError(t, stranger.client, http.MethodGet,
		"/v1/orgs/"+fx.OrgID, nil, http.StatusForbidden)
	assert.Equal(t, "forbidden", code, "non-member org view -> 403 via authz")

	// Random org ID: identical response.
	codeRandom := expectError(t, stranger.client, http.MethodGet,
		"/v1/orgs/"+uuid.NewString(), nil, http.StatusForbidden)
	assert.Equal(t, code, codeRandom,
		"foreign org and nonexistent org must be indistinguishable to a non-member")

	// Same rule applies to every org-scoped route.
	expectError(t, stranger.client, http.MethodGet,
		"/v1/orgs/"+fx.OrgID+"/members", nil, http.StatusForbidden)
	expectError(t, stranger.client, http.MethodPatch,
		"/v1/orgs/"+fx.OrgID, map[string]any{"name": "Hijacked"}, http.StatusForbidden)
}

// TestPersonalOrgInvariants: the registration-created personal org can never
// be deleted, even by its own owner, and never accepts members (409
// personal_workspace before any invitation row is created).
func TestPersonalOrgInvariants(t *testing.T) {
	user := registerUser(t, "personal")

	// The owner holds org.delete, passes authz, and is still rejected by
	// the service: 409 cannot_delete_personal_org.
	code := expectError(t, user.client, http.MethodDelete,
		"/v1/orgs/"+user.personalOrgID, nil, http.StatusConflict)
	assert.Equal(t, "cannot_delete_personal_org", code)

	// A stranger can't even reach the delete route for it.
	expectError(t, newClient(t), http.MethodDelete,
		"/v1/orgs/"+user.personalOrgID, nil, http.StatusUnauthorized)

	// Personal orgs never accept members: the owner passes the middleware
	// (member.invite) but the service blocks the invite with 409
	// personal_workspace before any invitation row exists.
	invitee := registerUser(t, "personal-invitee")
	roles := orgRolesByKind(t, user, user.personalOrgID)
	require.Contains(t, roles, "member", "personal orgs do get provisioned roles")
	code = expectError(t, user.client, http.MethodPost,
		"/v1/orgs/"+user.personalOrgID+"/members/invite",
		map[string]any{"role_id": roles["member"]}, http.StatusConflict)
	assert.Equal(t, "personal_workspace", code)

	// A stranger's invite is denied at the middleware; they never reach the
	// service guard.
	code = expectError(t, invitee.client, http.MethodPost,
		"/v1/orgs/"+user.personalOrgID+"/members/invite",
		map[string]any{"role_id": roles["member"]}, http.StatusForbidden)
	assert.Equal(t, "forbidden", code)

	// The invitee never became a member; the list is still just the owner.
	members := listMembers(t, user, user.personalOrgID)
	assert.True(t, memberIDs(members)[user.userID],
		"owner must remain a member of their personal org")
	assert.False(t, memberIDs(members)[invitee.userID],
		"the blocked invite must not have produced a membership")
}

// TestCrossOrgIsolation_ListIsScopedToOrg: an owner of org A can't list org
// B's members and vice versa. The actors belong to exactly one org each
// (the fixture's admin is a member of both and would legitimately get 200).
func TestCrossOrgIsolation_ListIsScopedToOrg(t *testing.T) {
	fx := seedOrg(t, "iso-a")

	// A separate user creates their own org, becoming its sole owner.
	bOwner := registerUser(t, "iso-b")
	bOrgID := createOrg(t, bOwner, "Isolation B")

	// Owner A (member of A only) cannot see B's members; owner B (member of
	// B only) cannot see A's members.
	expectError(t, fx.Owner.client, http.MethodGet,
		"/v1/orgs/"+bOrgID+"/members", nil, http.StatusForbidden)
	expectError(t, bOwner.client, http.MethodGet,
		"/v1/orgs/"+fx.OrgID+"/members", nil, http.StatusForbidden)

	// But each sees their own org's members.
	assert.Len(t, listMembers(t, fx.Owner, fx.OrgID), 4, "org A has owner+admin+member+viewer")
	assert.Len(t, listMembers(t, bOwner, bOrgID), 1, "org B has only its owner so far")
}

// TestInviteFlow_SingleUseToken covers the invite lifecycle: single-use
// tokens, foreign role IDs collapsing to 404, and duplicate-accept handling.
func TestInviteFlow_SingleUseToken(t *testing.T) {
	owner := registerUser(t, "inviteflow-owner")
	invitee := registerUser(t, "inviteflow-invitee")

	orgID := createOrg(t, owner, "Invite Flow Co")
	roles := orgRolesByKind(t, owner, orgID)

	// Invite with a role from ANOTHER org (the owner's personal org role).
	foreignRole := orgRolesByKind(t, owner, owner.personalOrgID)["member"]
	code := expectError(t, owner.client, http.MethodPost,
		"/v1/orgs/"+orgID+"/members/invite",
		map[string]any{"role_id": foreignRole}, http.StatusNotFound)
	assert.Equal(t, "membership_not_found", code,
		"a role ID scoped to a different org must collapse to not-found")

	// Invite with a random role ID: indistinguishable.
	codeRandom := expectError(t, owner.client, http.MethodPost,
		"/v1/orgs/"+orgID+"/members/invite",
		map[string]any{"role_id": uuid.NewString()}, http.StatusNotFound)
	assert.Equal(t, code, codeRandom)

	// Create one invitation and capture its raw token.
	inviteBody := expectStatus(t, owner.client, http.MethodPost,
		"/v1/orgs/"+orgID+"/members/invite",
		map[string]any{"role_id": roles["member"]}, http.StatusCreated, owner.bearer())
	var inviteEnv envelope
	require.NoError(t, json.Unmarshal(inviteBody, &inviteEnv))
	var inviteData struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(inviteEnv.Data, &inviteData))
	require.NotEmpty(t, inviteData.Token)

	// Accept once: 200, and the user is now a member.
	acceptBody := expectStatus(t, invitee.client, http.MethodPost,
		"/v1/auth/invitations/"+inviteData.Token+"/accept", nil, http.StatusOK, invitee.bearer())
	var acceptEnv envelope
	require.NoError(t, json.Unmarshal(acceptBody, &acceptEnv))
	var accepted struct {
		OrganizationID string `json:"organization_id"`
	}
	require.NoError(t, json.Unmarshal(acceptEnv.Data, &accepted))
	assert.Equal(t, orgID, accepted.OrganizationID)

	members := listMembers(t, owner, orgID)
	assert.True(t, memberIDs(members)[invitee.userID], "invitee must appear in the member list")
	assert.Equal(t, "member", roleKindOf(t, members, invitee.userID),
		"invitee must hold the invited role")

	// The SAME token cannot be accepted again: single-use invitation.
	code = expectError(t, invitee.client, http.MethodPost,
		"/v1/auth/invitations/"+inviteData.Token+"/accept", nil, http.StatusUnauthorized)
	assert.Equal(t, "invalid_token", code, "reusing an accepted invitation token must fail")

	// A second invitation into an org the user already belongs to is
	// rejected with 409 already_member; the UNIQUE violation is translated,
	// not surfaced as a 500.
	secondInvite := expectStatus(t, owner.client, http.MethodPost,
		"/v1/orgs/"+orgID+"/members/invite",
		map[string]any{"role_id": roles["member"]}, http.StatusCreated, owner.bearer())
	var secondEnv envelope
	require.NoError(t, json.Unmarshal(secondInvite, &secondEnv))
	var secondData struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(secondEnv.Data, &secondData))
	code = expectError(t, invitee.client, http.MethodPost,
		"/v1/auth/invitations/"+secondData.Token+"/accept", nil, http.StatusConflict)
	assert.Equal(t, "already_member", code)

	// The rejected accept didn't burn the token: the transaction rolled
	// back, so a retry hits the same conflict rather than a stale-token 401.
	code = expectError(t, invitee.client, http.MethodPost,
		"/v1/auth/invitations/"+secondData.Token+"/accept", nil, http.StatusConflict)
	assert.Equal(t, "already_member", code, "a rejected accept must not consume the invitation token")
}

// roleKindOf returns the role_kind of a member in a member list.
func roleKindOf(t *testing.T, members []memberView, userID string) string {
	t.Helper()
	for _, m := range members {
		if m.UserID == userID {
			return m.RoleKind
		}
	}
	t.Fatalf("member %s not found in list", userID)
	return ""
}

// TestRemoveMember_TakesEffectImmediately: a removed member drops off the
// list and their still-valid token loses all org access via the authz join.
func TestRemoveMember_TakesEffectImmediately(t *testing.T) {
	fx := seedOrg(t, "removal")

	expectStatus(t, fx.Owner.client, http.MethodDelete,
		"/v1/orgs/"+fx.OrgID+"/members/"+fx.Member.userID, nil, http.StatusNoContent, fx.Owner.bearer())

	// Gone from the member list.
	assert.False(t, memberIDs(listMembers(t, fx.Owner, fx.OrgID))[fx.Member.userID],
		"removed member must not appear in the member list")

	// The member's session still authenticates (sessions are user-global)
	// but authz now denies every org-scoped request.
	expectError(t, fx.Member.client, http.MethodGet,
		"/v1/orgs/"+fx.OrgID, nil, http.StatusForbidden)
}

// TestLeaveOrg_AnyMemberCanLeaveAndOrgAccessIsRevoked: any member can leave,
// and org access is revoked immediately. The viewer is the deliberate actor
// (the viewer role holds no member.* permissions, so a successful leave
// proves the route is genuinely authz-free).
func TestLeaveOrg_AnyMemberCanLeaveAndOrgAccessIsRevoked(t *testing.T) {
	fx := seedOrg(t, "leave")

	expectStatus(t, fx.Viewer.client, http.MethodPost,
		"/v1/orgs/"+fx.OrgID+"/leave", nil, http.StatusNoContent, fx.Viewer.bearer())

	// Gone from the member list.
	assert.False(t, memberIDs(listMembers(t, fx.Owner, fx.OrgID))[fx.Viewer.userID],
		"member who left must not appear in the member list")

	// The leaver's session still authenticates (sessions are user-global)
	// but authz now denies every org-scoped request.
	expectError(t, fx.Viewer.client, http.MethodGet,
		"/v1/orgs/"+fx.OrgID, nil, http.StatusForbidden)

	// Leaving again: the membership lookup finds nothing, 404 like a member
	// who never existed.
	code := expectError(t, fx.Viewer.client, http.MethodPost,
		"/v1/orgs/"+fx.OrgID+"/leave", nil, http.StatusNotFound)
	assert.Equal(t, "membership_not_found", code)
}

// TestLeaveOrg_LastOwnerCannotLeave pins the min-one-owner invariant on
// Leave: the last owner can't leave (409 last_owner), and once a co-owner
// exists the original owner can, which is how ownership transfers happen.
func TestLeaveOrg_LastOwnerCannotLeave(t *testing.T) {
	owner := registerUser(t, "leavelast")
	orgID := createOrg(t, owner, "Last Owner Co")

	// Sole owner trying to leave: same guard as remove/demote -> 409.
	code := expectError(t, owner.client, http.MethodPost,
		"/v1/orgs/"+orgID+"/leave", nil, http.StatusConflict)
	assert.Equal(t, "last_owner", code)

	// The rejected leave changed nothing: the owner is still a member.
	roles := orgRolesByKind(t, owner, orgID)
	assert.True(t, memberIDs(listMembers(t, owner, orgID))[owner.userID],
		"a rejected leave must not remove the owner")

	// Bring in a co-owner through the real invite+accept flow, then the
	// original owner is no longer the last owner and can leave.
	coowner := registerUser(t, "leavelast-coowner")
	inviteAndAccept(t, owner, coowner, orgID, roles["owner"])

	expectStatus(t, owner.client, http.MethodPost,
		"/v1/orgs/"+orgID+"/leave", nil, http.StatusNoContent, owner.bearer())

	// The org keeps exactly one owner, and the departed owner has lost all
	// org access.
	assert.Equal(t, 1, countRoleKind(listMembers(t, coowner, orgID), "owner"),
		"the co-owner must remain the sole owner after the original owner leaves")
	expectError(t, owner.client, http.MethodGet, "/v1/orgs/"+orgID, nil, http.StatusForbidden)
}

// TestLeaveOrg_NonMemberGets404: the Leave route has no Authz middleware,
// so the 404 for non-members comes from the membership lookup itself, and
// a foreign user and a random org ID collapse to the same 404.
func TestLeaveOrg_NonMemberGets404(t *testing.T) {
	fx := seedOrg(t, "leavestranger")

	// A user who exists (and owns their own org) but is not a member here.
	stranger := registerUser(t, "leavestranger-u")
	code := expectError(t, stranger.client, http.MethodPost,
		"/v1/orgs/"+fx.OrgID+"/leave", nil, http.StatusNotFound)
	assert.Equal(t, "membership_not_found", code)

	// A random org ID is indistinguishable from the real foreign org.
	codeRandom := expectError(t, stranger.client, http.MethodPost,
		"/v1/orgs/"+uuid.NewString()+"/leave", nil, http.StatusNotFound)
	assert.Equal(t, code, codeRandom,
		"foreign org and nonexistent org must be indistinguishable to a non-member")

	// Unauthenticated: rejected by Authn before any membership lookup.
	code = expectError(t, newClient(t), http.MethodPost,
		"/v1/orgs/"+fx.OrgID+"/leave", nil, http.StatusUnauthorized)
	assert.Equal(t, "missing_token", code)
}

// createOrg creates a business org as the given user and returns its ID.
func createOrg(t *testing.T, owner *testUser, name string) string {
	t.Helper()
	respBody := expectStatus(t, owner.client, http.MethodPost, "/v1/orgs",
		map[string]any{"name": name}, http.StatusCreated, owner.bearer())
	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &created))
	require.NotEmpty(t, created.ID)
	return created.ID
}
