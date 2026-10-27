# Threat model

Scope: one deployment of this service, one database, browser and API clients. Each threat lists the mitigation, the test that covers it, and what is still left over.

## 1. Session theft and fixation

**Threat.** An attacker steals an access or refresh token and keeps using it after the user logs out, or plants a session the victim later uses.

**Mitigation.**
- Tokens are 256-bit random values, not JWTs. Only the SHA-256 hash is stored, so a database leak hands out no usable token.
- Sessions live in the database. `Authn` looks up the hash on every request and rejects revoked or expired rows, so logout is immediate.
- Refresh tokens rotate on every use and are bound to a token family.
- Cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, scoped to `/v1/auth`.
- A suspended user fails the session lookup on the next request.

**Test.** `TestAuthLifecycle_RegisterLoginRefreshLogout`, `TestAuthLogoutAll_RevokesEverySession`, `TestLogin_SuspendedUserReturns403`.

**Residual risk.** A stolen access token works until it expires or the session is revoked. There is no device binding. Session lifetime is sliding: every refresh starts a new refresh window.

## 2. Cross-site request forgery

**Threat.** A malicious site makes the victim's browser send the refresh cookie to `/v1/auth/refresh` and mints a new session.

**Mitigation.**
- Access tokens travel in the `Authorization` header, which a browser does not attach automatically.
- The refresh cookie is the only cookie-authenticated route. It is `SameSite=Strict` and requires a double-submit `X-CSRF-Token` header, compared with `subtle.ConstantTimeCompare`.
- The CSRF value is returned in the login, register and refresh response bodies, because the cookie path is not visible to a browser app served from another path.
- `frame-ancestors 'none'` and `X-Frame-Options: DENY` block framing.

**Test.** `TestAuthRefresh_CSRFEnforcement`, `TestAuthResponsesExposeCSRFToken`.

**Residual risk.** The double-submit token is not bound to the session. An XSS bug on the API origin would defeat it, as with any double-submit scheme.

## 3. Refresh token replay

**Threat.** An attacker with a stolen refresh token races the legitimate client, or replays a token after rotation, to keep a parallel session alive.

**Mitigation.**
- Rotation runs in one transaction: `SELECT ... FOR UPDATE` on the session row, a conditional revoke that must affect exactly one row, then the insert of the next session.
- A token that is already revoked, or a conditional revoke that affects zero rows, is treated as replay. The whole token family is revoked and `token.replay_detected` is audited.
- A failed rotation rolls back, so a client never loses its token without receiving the replacement.

**Test.** `TestAuthRefresh_ReplayRevokesWholeFamily`, `TestRefresh_ConcurrentReplayYieldsOneToken`.

**Residual risk.** Strict rotation logs out a client that sends two refreshes at once (two tabs). That is the intended trade-off. A replay revokes the legitimate client's new token too.

## 4. Cross-tenant access and privilege escalation

**Threat.** A member of one organization reads or changes another organization's data by changing an ID, or escalates their own role.

**Mitigation.**
- Org-scoped routes carry `{org_id}`. `Authz` checks the caller's active membership and one fixed permission before the handler runs.
- Org-scoped queries pair the resource ID with `organization_id`, so a foreign row returns the same 404 as a missing one.
- Role grants have a composite foreign key to the organization, so a membership cannot reference another tenant's role even if application code is wrong.
- Only an owner can grant or revoke the owner role, and the last owner cannot be removed, demoted or leave. The owner count is read with `FOR UPDATE`.
- A deleted or suspended organization fails the permission check, and soft delete revokes outstanding invitations.

**Test.** `TestIDOR_CrossOrgMemberDeleteIs404`, `TestNonMemberOrgAccess`, `TestCrossOrgIsolation_ListIsScopedToOrg`, `TestLastOwnerCannotBeRemovedOrDemoted`, `TestOwnerActionRestricted`, `TestDeletedOrganization_IsClosedToMembers`.

**Residual risk.** Isolation is enforced by queries, not row-level security. Any new repository method that forgets the org predicate is a cross-tenant read. A database compromise exposes every tenant.

## 5. Credential guessing and resource exhaustion

**Threat.** Password guessing, credential stuffing, oversized requests, or a flood that exhausts the connection pool.

**Mitigation.**
- Argon2id hashing with a dummy hash on unknown users, so login timing does not reveal whether an account exists.
- Token-bucket limits per client IP on auth routes and per organization on org routes.
- Request bodies are capped at 64 KiB; the HTTP server sets read, write, header and idle timeouts.
- Database queries use a timeout on the login and audit paths, and the pool is bounded.

**Test.** `TestRateLimiting_IsKeyedPerIP`, `TestRateLimiting_OrgRouteBurst`, `TestRequestBodyLimit`.

**Residual risk.** There is no per-account lockout or MFA. Rate limiting is per process and trusts `X-Forwarded-For`, so a proxy must overwrite that header, and multiple replicas multiply the limit. Login still costs one Argon2 verification per request.

## Reporting

Open an issue with the route, the request, and the observed response. Do not include live tokens or personal data.
