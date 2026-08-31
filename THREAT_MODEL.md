# Threat Model — Multi-Tenant Authorization Service

This document maps the four threats claimed for this service — **session fixation,
CSRF, token replay, and IDOR-based privilege escalation** — to the concrete
implementations that mitigate them, and gives a reproduction you can run against the
service to verify each one. It ends with the defense-in-depth patterns (owner
invariants, collapsed-error scoping) and an honest list of residual risks found by the
integration suite.

**How this was verified:** every mitigation below was read from the actual source
(`internal/auth`, `internal/middleware`, `internal/membership`, the repositories) and
cross-checked against the integration tests in `integration/`. Where a claim relies on a
test, the test name is cited. Where the evidence is weaker, it says so.

The service model, briefly: an opaque access token (`Authorization: Bearer <token>`,
DB-backed, instantly revocable — not a JWT) plus a rotating refresh token in an
`HttpOnly` cookie. Org-scoped routes require both authentication and a specific
permission in the target organization. See [README.md](README.md) and
[openapi.yaml](openapi.yaml) for the full surface.

---

## 1. Session Fixation

### The attack

Session fixation is when an attacker forces a victim's session identifier to a value the
attacker already knows, so that after the victim logs in, the attacker's known
identifier is authenticated. Classic vectors: sending the victim a link containing a
pre-set session ID, or setting a cookie before login. It matters when the server
*accepts client-supplied* session identifiers, or fails to issue a fresh session at
authentication time.

### The mitigation

There is no client-controlled session identity anywhere in this system, and every
authentication event mints a brand-new session:

- **Server-only, high-entropy tokens.** Session tokens are 256-bit random values from
  `crypto/rand` (`generateOpaqueToken`, `internal/auth/tokens.go`), base64url-encoded.
  No endpoint accepts a session identifier from the client; `Authn` middleware only
  looks up the hash of whatever bearer token was presented. There is nothing a client
  can set in advance.
- **Fresh session per login/register.** `Repository.CreateSession`
  (`internal/auth/repository.go`) inserts a new `sessions` row with a **new**
  `token_family_id` on every login and registration — the column default
  `gen_random_uuid()` is used, and a family ID is only carried forward by the rotation
  path (`CreateSessionInFamily`), which is itself only reachable with a valid refresh
  token. An attacker's pre-set "session" state cannot survive into an authenticated
  session because no pre-set state exists to survive.
- **Rotation and revocation.** Every refresh replaces the session row
  (`Service.Refresh` in `internal/auth/service.go`); logout and logout-all revoke the
  current session or all sessions (`RevokeSession`, `RevokeAllSessionsForUser`), and
  the `sessions` table stores only SHA-256 hashes, so even a leaked database cannot be
  used to reconstruct a live session.

### How to verify

```bash
# login twice as the same user — the two sessions must be distinct rows with
# distinct access tokens and distinct refresh-token families:
curl -s -c jar1.txt -X POST localhost:6070/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"identifier":"ada@example.com","password":"Sup3rSecret!123"}'
curl -s -c jar2.txt -X POST localhost:6070/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"identifier":"ada@example.com","password":"Sup3rSecret!123"}'
# compare the access tokens in the two responses, then:
curl -s -b jar1.txt -H "Authorization: Bearer <token1>" localhost:6070/v1/auth/sessions
# -> two entries; exactly one is "current": the session that issued the presented token

# after logout, the presented token is dead everywhere (no expiry grace):
curl -s -b jar1.txt -X POST localhost:6070/v1/auth/logout \
  -H "Authorization: Bearer <token1>"   # 204
curl -s -H "Authorization: Bearer <token1>" localhost:6070/v1/me/organizations
# -> 401 invalid_token
```

**Test coverage:** `TestAuthLifecycle_RegisterLoginRefreshLogout`
(`integration/auth_test.go`) — fresh token per login, two live sessions, exact-one
`current`, post-logout rejection. Honest caveat: there is **no dedicated
session-fixation test**; the property is covered indirectly by the lifecycle test and by
the fact that no code path accepts a client-supplied session ID.

---

## 2. CSRF (Cross-Site Request Forgery)

### The attack

A malicious site makes the victim's browser send a state-changing request to a site
where the victim is authenticated via **automatic credentials** (cookies). The browser
attaches the cookie; the server can't tell the request came from the attacker's page.
The classic dangerous surface is cookie-authenticated endpoints that mutate state.

### The mitigation

This API deliberately keeps cookie-authenticated state changes to exactly one endpoint:
`POST /v1/auth/refresh` (everything else authenticates with the `Authorization` header,
which browsers never attach automatically). That one endpoint is protected by a
**double-submit cookie** check:

- On login/register/refresh, the server sets two cookies
  (`setAuthCookies`, `internal/auth/cookies.go`): `refresh_token` (`HttpOnly`) and
  `csrf_token` (JS-readable — its job is to be echoed back, so it must be readable by
  same-origin script).
- `verifyCSRF` (`internal/auth/cookies.go`) requires the `X-CSRF-Token` header to equal
  the `csrf_token` cookie, compared with `subtle.ConstantTimeCompare`. A cross-site
  attacker can force the browser to *send* the cookie, but cannot *read* it to set the
  matching header (that requires same-origin script access to `document.cookie`).
- The check runs **before any token validation** (`AuthHandler.Refresh`,
  `internal/auth/handler.go`), so a forged request is rejected without touching the
  refresh token at all. Failure is `403` with error code `csrf_check_failed`.
- Defense in depth: both cookies are `Secure` + `SameSite=Strict` + scoped to
  `Path=/v1/auth`; `SecurityHeaders` middleware sets `X-Frame-Options: DENY` and CSP
  `frame-ancestors 'none'` (clickjacking is a related attack SameSite doesn't cover);
  `CORS` only reflects explicitly allowlisted origins and never sends
  `Access-Control-Allow-Origin: *` with credentials.

### How to verify

```bash
# 1. get a session and capture cookies:
curl -s -c jar.txt -X POST localhost:6070/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"Sup3rSecret!123","first_name":"Ada","last_name":"Lovelace"}'

# 2. correct refresh_token cookie, NO X-CSRF-Token header:
curl -i -b jar.txt -X POST localhost:6070/v1/auth/refresh
# -> HTTP/1.1 403
#    {"success":false,"error":{"code":"csrf_check_failed","message":"CSRF validation failed"}}

# 3. cookie + WRONG header value:
curl -i -b jar.txt -X POST localhost:6070/v1/auth/refresh -H 'X-CSRF-Token: definitely-not-the-cookie'
# -> HTTP/1.1 403, code csrf_check_failed

# 4. cookie + matching header (read csrf_token from jar.txt):
curl -i -b jar.txt -X POST localhost:6070/v1/auth/refresh -H "X-CSRF-Token: <value from jar.txt>"
# -> HTTP/1.1 200, token refreshed, both cookies re-issued
```

**Test coverage:** `TestAuthRefresh_CSRFEnforcement` (`integration/auth_test.go`) — no
header → 403, wrong header → 403, matching header → 200.

---

## 3. Token Replay (Refresh-Token Reuse)

### The attack

A stolen refresh token is used by the attacker to mint new access tokens indefinitely.
Classically the victim doesn't notice because the token "still works." The same family
of attack includes replaying an access token after the user logged out.

### The mitigation

Refresh tokens **rotate on every use**, and reuse is treated as theft:

- **Rotation.** `Service.Refresh` (`internal/auth/service.go`) revokes the presented
  session and inserts a rotated one with the same `token_family_id` in a single
  transaction (`RevokeSession` + `CreateSessionInFamily`, `internal/auth/repository.go`).
  A refresh token is valid for exactly one use.
- **Reuse detection → whole-family revocation.** If the presented refresh token hashes
  to a `revoked` session, the service assumes the token leaked (or a legitimate client
  retried a lost response) and calls `RevokeFamily(ctx, session.TokenFamilyID)` — every
  session sharing the family, including the legitimate rotated one, is revoked. The
  event is written to the audit log with action `token.replay_detected` and
  `token_family_id` metadata. The client gets the same `401 invalid_token` it would get
  for a token that never existed, so the attacker learns nothing.
- **Access tokens are revocable too.** Because access tokens are DB-backed rows, not
  self-verifying JWTs, `Authn` checks the `revoked` flag and expiry on every request
  (`GetActiveSessionByAccessTokenHash`): a logged-out or family-revoked access token
  stops working immediately.
- **Invitations use the same discipline.** Invitation tokens are stored as SHA-256
  hashes and are single-use (`MarkInvitationAccepted`), and invitation rotation is
  revoke-and-reissue (`RotateInvite`).

### How to verify

```bash
# 1. register; snapshot generation-1 cookies (jar1) and csrf value:
curl -s -c jar1.txt -X POST localhost:6070/v1/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"Sup3rSecret!123","first_name":"Ada","last_name":"Lovelace"}'

# 2. refresh once — succeeds, rotates to generation 2 (jar2):
curl -s -c jar2.txt -b jar1.txt -X POST localhost:6070/v1/auth/refresh \
  -H "X-CSRF-Token: <gen1 csrf from jar1.txt>"
# -> 200

# 3. replay the generation-1 refresh token (present gen-1 cookie + gen-1 CSRF pair;
#    the CSRF check runs first, so the pair must match):
curl -i -b jar1.txt -X POST localhost:6070/v1/auth/refresh \
  -H "X-CSRF-Token: <gen1 csrf from jar1.txt>"
# -> HTTP/1.1 401 {"success":false,"error":{"code":"invalid_token","message":"invalid token"}}

# 4. the KEY assertion — the legitimate generation-2 token is now dead too:
curl -i -b jar2.txt -X POST localhost:6070/v1/auth/refresh \
  -H "X-CSRF-Token: <gen2 csrf from jar2.txt>"
# -> HTTP/1.1 401 invalid_token   (family revocation)

# 5. the rotated access token no longer authenticates:
curl -s -H "Authorization: Bearer <gen2 access token>" localhost:6070/v1/me/organizations
# -> HTTP/1.1 401 invalid_token
```

**Test coverage:** `TestAuthRefresh_ReplayRevokesWholeFamily` (`integration/auth_test.go`)
— exactly the sequence above, including the family-revocation assertion.
`TestAuthLifecycle_RegisterLoginRefreshLogout` covers post-logout access-token
revocation. `TestInviteFlow_SingleUseToken` covers single-use invitation tokens.

---

## 4. IDOR-Based Privilege Escalation

### The attack

Insecure Direct Object Reference: an authenticated user accesses or mutates another
tenant's resources by substituting IDs (an org ID, member ID, role ID, or invitation ID)
that they shouldn't be able to reach. "Privilege escalation" here is the cross-tenant
flavor — using your access in org A to touch org B.

### The mitigation

Three layers, each verifiable:

1. **Membership-gated authorization before any handler runs.** `Authz` middleware
   (`internal/middleware/authz.go`) parses `{org_id}` from the route, calls
   `CheckPermission(userID, orgID, permissionKey)`, and only then sets the trusted org
   ID on the request context. The raw path parameter is never trusted by handlers —
   `requestctx.OrgID` is set once, by Authz, after validation. A caller who is not an
   active member of the org gets `403 forbidden` regardless of what the handler would
   do. `CheckPermission` is a single parameterized query joining
   memberships → role → permissions (`internal/authz/repository.go`).
2. **Every org-scoped query filters on `(id, organization_id)` together.**
   Repositories never look up an org-scoped resource by bare ID:
   - `GetInvitationByID(orgID, invitationID)` — `WHERE id = $1 AND organization_id = $2`
   - `GetRoleKindByID(orgID, roleID)` — same pairing
   - `RemoveMember(orgID, userID)`, `UpdateMemberRole(orgID, userID, roleID)` — scoped
     deletes/updates that affect zero rows for foreign targets
   - member listing and role listing join from the authenticated org ID
3. **Collapsed errors — foreign and nonexistent are indistinguishable.**
   Cross-org targets return the same status, code, and message as targets that don't
   exist (`membership_not_found` for members/roles and for non-member leave attempts,
   `invitation_not_found` for org-scoped invitation IDs, `forbidden` at the middleware
   for non-member org access). This is deliberate anti-enumeration: an attacker cannot
   distinguish "that ID exists in another tenant" from "that ID doesn't exist."

### How to verify

```bash
# A owns org A; B is a registered user with their own unrelated personal org.
# A tries to delete B from org A — B is not a member of org A:
curl -i -X DELETE localhost:6070/v1/orgs/<orgA>/members/<userB> \
  -H "Authorization: Bearer <tokenA>"
# -> HTTP/1.1 404 {"success":false,"error":{"code":"membership_not_found",...}}

# A random UUID gets the IDENTICAL response:
curl -i -X DELETE localhost:6070/v1/orgs/<orgA>/members/<random-uuid> \
  -H "Authorization: Bearer <tokenA>"
# -> HTTP/1.1 404, code membership_not_found, same message

# B (not a member of org A) tries to view org A, and a random org ID:
curl -i -H "Authorization: Bearer <tokenB>" localhost:6070/v1/orgs/<orgA>
curl -i -H "Authorization: Bearer <tokenB>" localhost:6070/v1/orgs/<random-uuid>
# -> both HTTP/1.1 403 forbidden — foreign org and nonexistent org are indistinguishable

# A role ID from another org collapses to not-found on invite:
curl -i -X POST localhost:6070/v1/orgs/<orgA>/members/invite \
  -H "Authorization: Bearer <tokenA>" -H 'Content-Type: application/json' \
  -d '{"role_id":"<roleID from B's org>"}'
# -> HTTP/1.1 404 membership_not_found
```

**Test coverage:** `TestIDOR_CrossOrgMemberDeleteIs404` (foreign user and random UUID
byte-identical), `TestNonMemberOrgAccess` (foreign org and random org ID identical
403s, incl. PATCH), `TestCrossOrgIsolation_ListIsScopedToOrg` (org A owner can't list
org B's members), `TestInviteFlow_SingleUseToken` (foreign role ID collapses to 404),
`TestRemoveMember_TakesEffectImmediately` (removal takes effect via the authz join
immediately).

---

## Defense in depth: owner invariants and the scoping pattern

Beyond the four named threats, two patterns are load-bearing for tenant isolation and
are worth reviewing on their own:

**Owner invariants** (`internal/membership/service.go`, backed by
`CountActiveOwners` with `FOR UPDATE` row locks in `internal/membership/repository.go`).
The generic permission model cannot express "only for non-owner targets," so
service-layer rules sit above the middleware check, executed inside the same
transaction as the mutation:

- The **last owner** cannot be removed, demoted, or leave — `409 last_owner`
  (`ErrLastOwner`), enforced on `Remove`, `AssignRole`, **and** `Leave`, with a
  row-locked count so two concurrent removals can't both read "2 owners."
- Only an **owner** can remove an owner, grant **or** revoke owner status (the
  owner-action restriction in `AssignRole` fires in both directions), or invite/rotate
  into the owner role — `403 owner_action_restricted` (`ErrOwnerActionRestricted`).
- **Personal organizations** (created exactly once per user, at registration) can never
  be deleted — `409 cannot_delete_personal_org` (`ErrCannotDeletePersonalOrg`) — and
  never accept members: `Invite` rejects them with `409 personal_workspace`
  (`ErrPersonalWorkspace`) before any invitation row is created. Org `type` is never
  accepted from any request, so "personal" is not a flag a caller can forge.

Tests: `TestLastOwnerCannotBeRemovedOrDemoted`, `TestOwnerActionRestricted`,
`TestPersonalOrgInvariants`, and the leave suite
`TestLeaveOrg_AnyMemberCanLeaveAndOrgAccessIsRevoked` /
`TestLeaveOrg_LastOwnerCannotLeave` / `TestLeaveOrg_NonMemberGets404`
(`integration/membership_test.go`).

**The scoping pattern as a whole.** Every cross-tenant question in the codebase is
answered by one of exactly two shapes: (a) an `(id, organization_id)` pair in the
WHERE clause (single-resource lookups), or (b) a join from the caller's own
memberships (`GET /me/organizations` — inherently cross-tenant, scoped by `user_id`).
There are no other shapes. That uniformity is what makes "no IDOR" a reviewable claim:
auditing the repository layer for a query that trusts a bare ID is a mechanical scan,
not a judgment call. Additionally, every Authz decision — allowed or denied — is
recorded to `authz_decisions` (`RecordDecision`, called from the middleware), so a
reviewer can answer "what did this user attempt, and when" after the fact; and the
`/authz-decisions` endpoint is itself protected by `audit_log.view`, so the trail is
only readable by those already entitled to see it.

---

## Residual risks and known gaps

Accuracy over marketing: these are real findings from the integration suite and the
source read, not hypotheticals.

**Fixed since the previous revision (verified in the working tree):**

- **Personal orgs accepting members** — `Invite` now returns `409 personal_workspace`
  before any invitation row is created (the existing `cannot_delete_personal_org` guard
  on `Delete` is unchanged).
- **Non-owner demoting a non-last owner** — `AssignRole` now applies the owner-action
  restriction in both directions: an admin granting *or* revoking owner status gets
  `403 owner_action_restricted`; the last-owner guard (`409 last_owner`) is unchanged.
- **Registration without `last_name` returning 500** — `users.last_name` is now
  nullable (`migrations/000001`) and an omitted `last_name` is stored as NULL;
  registration succeeds with 201 (`TestRegisterWithoutLastName_Succeeds`).
- **Duplicate invite accept returning 500** — `CreateMembership` translates the
  memberships `UNIQUE(user_id, organization_id)` violation to `409 already_member`.
- **Suspended-user login returning 500** — `Login` returns `ErrUserSuspended` for any
  `status != 'active'` account; `response.HandleError` now maps it to
  `403 user_suspended` (`TestLogin_SuspendedUserReturns403`).

Remaining:

1. **`X-Forwarded-For` is trusted for rate-limit keys.** `utils.ClientIP` prefers XFF
   over `RemoteAddr`; behind a proxy that appends rather than overwrites, a client can
   spoof the key. The code comment flags this — it must be verified against the actual
   deployment's proxy config. Accepted risk (deployment-config).
2. **Penetration-test artifacts live outside the repo.** The claim of a "self-run
   penetration pass (OWASP ZAP or equivalent)" is substantiated by the manual
   verification pass and substitute passive/probe sweep documented in
   [SECURITY_SCAN.md](SECURITY_SCAN.md); the raw evidence artifacts and the ZAP
   failure logs live in `/tmp/opencode/mtas-sec-r2/` (see the scan report's evidence
   index). The automated ZAP component itself was blocked by environment network
   limits and was not executed.
3. **Session fixation has no dedicated test** (see §1) — it is covered indirectly by
   lifecycle and rotation tests.

Item 1 is a correctness/operational risk; items 2–3 are evidence/coverage notes.
