# Multi-Tenant Authorization Service (MTAS)

A production-grade Go/PostgreSQL RBAC and session-management backend for isolated
tenant organizations. Users register, get a personal workspace, create business
organizations, and invite members into roles backed by a permission catalog; every
authorization decision is written to an auditable trail. The security story is the
point: opaque revocable tokens with refresh rotation, double-submit CSRF protection,
token-replay detection, IDOR-resistant org scoping, and a documented threat model
([THREAT_MODEL.md](THREAT_MODEL.md)) — each threat matched to a concrete mitigation and
an integration test that proves it.

This repository is the implementation behind three claims that matter:

- **RBAC + audit trail** — org-scoped roles with a seeded permission catalog
  (`org.*`, `member.*`, `role.*`, `audit_log.view`, plus a domain-agnostic
  `resource.*` set) and a complete `authz_decisions` trail recording **every** check,
  allowed *and* denied (`GET /v1/orgs/{org_id}/authz-decisions`).
- **Threat model + mitigations** — session fixation, CSRF, token replay, and
  IDOR-based privilege escalation, each with an implemented mitigation and a
  verification path. See [THREAT_MODEL.md](THREAT_MODEL.md) and
  [SECURITY_SCAN.md](SECURITY_SCAN.md) (the report of the security-verification pass).
- **Refresh rotation + rate limiting** — refresh tokens rotate on every use and carry a
  `token_family_id`; replaying a revoked token revokes the whole family. Rate limiting is
  token-bucket (5 rps, burst 10): per client IP on pre-tenant auth routes, per
  organization on every `{org_id}`-scoped route.

> **Scope honesty (read before you judge).** There are **no resource endpoints** in this
> build — the original task list's `resource.create/get/update/delete` are not
> implemented, and the `resource.*` permissions are seeded but unused. What *is*
> implemented and tested is the authorization *engine*: tenants, roles, permissions,
> membership, invitations, sessions, and the decision trail. Also deliberately absent:
> role administration (create/edit/delete custom roles), password change/reset, and
> ownership transfer — see [What's deliberately not built](#whats-deliberately-not-built).

---

## Architecture (the reasoning, not the file tree)

### Repository pattern via a shared `db.Querier`

Every domain repository (`auth`, `organization`, `membership`, `authz`, `audit`, `role`)
is constructed against `db.Querier` (`pkg/db/dbquerier.go`), an interface satisfied by
both `*pgxpool.Pool` and `pgx.Tx`. Repositories **never start transactions** — the
service layer composes them with `pgx.BeginFunc`, handing `NewRepository(tx)` to each
domain repo it needs inside the same unit of work.

- Registration (`auth.Service.Register`) creates user **+** personal org **+** owner
  membership **+** first session in one transaction; an org with no owner, or a user
  with no session, is a broken state nothing downstream expects.
- Invitation accept (`membership.Service.Accept`) marks the invitation accepted **and**
  inserts the membership in one transaction, so a token can't be redeemed twice even
  under a concurrent race.
- Refresh rotation (`auth.Service.Refresh`) revokes the old session and inserts the
  rotated one atomically — a half-rotated session would leave the client with nothing.

This is the pattern that keeps multi-domain operations atomic without leaking
transaction logic into repositories.

### IDOR mitigation: every org-scoped lookup filters on `(id, organization_id)`

Repositories never query by a bare ID when the ID is org-scoped. `GetInvitationByID`,
`GetRoleKindByID`, `RemoveMember`, and the rest always pair the resource ID with the
org ID from the authenticated route. A resource belonging to a different org therefore
returns **exactly the same "not found"** as a nonexistent ID — the system does not just
authorize correctly, it makes cross-org and nonexistent targets *indistinguishable*
(anti-enumeration). The `Authz` middleware validates the caller's active membership
against `{org_id}` before any handler runs, so the raw path parameter is never trusted.

### Owner invariants (service layer, above the generic permission check)

Role *permissions* can't express "grant this, but only for non-owner targets", so the
owner rules live in `internal/membership/service.go` and run inside transactions against
a row-locked owner count (`CountActiveOwners ... FOR UPDATE`, in the membership
repository):

- The last owner can never be removed, demoted, **or leave** — `409 last_owner`, on
  `Remove`, `AssignRole`, and the self-service `Leave` endpoint alike.
- Only an owner can grant **or** revoke the owner role, remove an owner, or
  invite/rotate into the owner role — `403 owner_action_restricted` (owner-only in
  both directions: granting *and* revoking owner status).
- Personal organizations (created once per user at registration) can never be deleted —
  `409 cannot_delete_personal_org` — and never accept members: `Invite` returns
  `409 personal_workspace`; `type` is never read from any request.

### Tokens: opaque and revocable, not JWTs

Passwords are argon2id-hashed (`internal/auth/password.go`, `m=19456,t=2,p=1`, PHC
format, constant-time compare, dummy-hash timing equalization on login). Session tokens
are **256-bit random opaque tokens, stored as SHA-256 hashes** (`internal/auth/tokens.go`)
— deliberately *not* JWTs, because a server-side session row gives immediate revocation:
`Authn` looks the session up by hash and rejects anything revoked or expired, so a
logged-out token dies instantly, no blacklist, no TTL grace. The raw token exists only
in memory and in the one response that returns it; a leaked database hands out no usable
tokens.

### CSRF: double-submit cookie, enforced on the one cookie-authenticated route

Access tokens travel in the `Authorization` header (never auto-attached by browsers, so
no CSRF exposure). The refresh token travels in an `HttpOnly` cookie — and
`POST /v1/auth/refresh` is therefore protected by a double-submit check
(`internal/auth/csrf.go` + `cookies.go`): the client must echo the JS-readable
`csrf_token` cookie in the `X-CSRF-Token` header, compared with
`subtle.ConstantTimeCompare`. Cookies are `Secure` + `SameSite=Strict` + scoped to
`Path=/v1/auth`, and the security-headers middleware sets `frame-ancestors 'none'` as
clickjacking defense-in-depth.

### Request context and middleware stack

`internal/requestctx` carries `user_id` / `org_id` / `session_id` / `request_id`
through the chain. The stack, wired in `cmd/main.go` (outermost first):

```
Recovery → RequestLogger (X-Request-ID) → SecurityHeaders → CORS
        → per-route: RateLimiter → Authn → Authz → handler
```

`Authn` answers only "who is this" (bearer → session → user ID); `Authz` answers "can
this user, in this org, do X" for the one permission key the route was registered with
(`Authz(repo, "member.invite")`, never inferred from method/path). Rate limiters are
keyed by `utils.ClientIP` (prefers `X-Forwarded-For`) for auth routes and by the
`{org_id}` path value for org routes. Health routes (`/health`, `/health/live`,
`/health/ready`) are registered on a separate mux and bypass the whole stack.

### Route design: `{org_id}` in the path

Org-scoped routes carry the tenant in the path (`Go 1.22+` `r.PathValue`) rather than a
header — a deliberate structural choice: the authz middleware reads it from one place,
logs it in the decision trail, and keys rate limiting off it. Two routes are inherently
cross-tenant and take no `{org_id}`: `POST /orgs` and `GET /me/organizations` (both
Authn-only); the invitation-accept route resolves the org from the token instead.

---

## Setup

### Prerequisites

- **Go 1.26+** (the module declares `go 1.26.2` in `go.mod`)
- **Docker** — for the local PostgreSQL (via `compose.yaml`) and for the integration
  test suite, which spins up a throwaway `postgres:18` container

### Environment variables

The server reads these from the environment (via `godotenv`, i.e. a `.env` file in the
working directory). This is the **real, complete** list from `pkg/config/config.go`:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `APP_NAME` | yes | — | Application name (only validated non-empty). |
| `APP_PORT` | yes | — | HTTP listen port, e.g. `6070`. |
| `APP_ENV` | yes | — | Must be `production` or `development` (validated). |
| `DB_URL` | yes | — | Full PostgreSQL DSN, e.g. `postgres://mtas:mtas@localhost:5432/mtas?sslmode=disable`. |
| `JWT_ACCESS_TTL` | no | `10m` | Access token lifetime (`time.ParseDuration` format). |
| `JWT_REFRESH_TTL` | no | `720h` | Refresh token / session lifetime. |
| `CORS_ALLOWED_ORIGINS` | yes | — | Comma-separated origin allowlist (non-empty required). |

**Known mismatch:** `.env.example` in this repo is stale — it documents
`DATABASE_URL`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_PORT`, `ACCESS_TOKEN_TTL`, and
`REFRESH_TOKEN_TTL`, none of which `pkg/config` reads (the code reads `DB_URL` and
`JWT_ACCESS_TTL`/`JWT_REFRESH_TTL`). `compose.yaml` *does* read `DB_NAME` / `DB_USER` /
`DB_PASSWORD` / `DB_PORT` for the Postgres container. A working `.env` therefore looks
like:

```dotenv
APP_NAME=mtas
APP_PORT=6070
APP_ENV=development
DB_URL=postgres://mtas:mtas@localhost:5432/mtas?sslmode=disable
JWT_ACCESS_TTL=10m
JWT_REFRESH_TTL=720h
CORS_ALLOWED_ORIGINS=http://localhost:5173

# consumed by compose.yaml for the Postgres container (not by the app):
DB_NAME=mtas
DB_USER=mtas
DB_PASSWORD=mtas
DB_PORT=5432
```

### Run it

```bash
# 1. Start PostgreSQL (reads DB_* vars from .env)
docker compose up -d

# 2. Apply migrations — there is no migrate tool in this repo; the four
#    migrations run in order (the integration harness applies them the same way).
#    With the compose container:
for f in migrations/*.up.sql; do
  docker exec -i mtas-postgres psql -U "$DB_USER" -d "$DB_NAME" < "$f"
done
# (or with a local psql:  psql "$DB_URL" -f "$f"  for each file, in order)

# 3. Run the server (loads ./.env, listens on APP_PORT)
make run          # = go run ./cmd
```

Migration order matters: `000001` schema → `000002` seed permissions →
`000003` seed template roles → `000004` org-provisioning function/trigger.

Smoke test:

```bash
curl -s localhost:6070/health/ready
curl -s -X POST localhost:6070/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"Sup3rSecret!123","first_name":"Ada","last_name":"Lovelace"}'
```

## API reference

The full OpenAPI 3.1 spec is in **[openapi.yaml](openapi.yaml)** — every endpoint,
schema (derived from the Go request/response types), permission requirement, status
code, and error code, with realistic examples. There is **no Swagger UI / Redoc server
in this repo**; to view it, load `openapi.yaml` into any OpenAPI viewer, e.g.:

```bash
npx --yes @redocly/cli preview-docs openapi.yaml
# or: npx --yes @redocly/cli lint openapi.yaml   (validation, no server)
```

Quick orientation (all API routes are under `/v1`):

| Area | Endpoints |
|---|---|
| Auth (per-IP rate limit, no authn) | `POST /auth/login`, `POST /auth/register`, `POST /auth/refresh` |
| Auth (bearer required) | `POST /auth/logout`, `POST /auth/logout-all`, `GET /auth/sessions` |
| Invitations | `POST /auth/invitations/{token}/accept` (authn + per-IP limit) |
| Organizations | `POST /orgs`, `GET /me/organizations` (authn) |
| | `GET` / `PATCH` / `DELETE /orgs/{org_id}` (`org.view` / `org.update` / `org.delete`) |
| Members | `GET /orgs/{org_id}/members` (`member.view`), `POST .../members/invite` (`member.invite`), `DELETE .../members/{user_id}` (`member.remove`), `PATCH .../members/{user_id}/role` (`member.assign_role`), `POST .../invitations/{invitation_id}/rotate` (`member.invite`), `POST .../leave` (any active member; no permission) |
| Roles | `GET /orgs/{org_id}/roles` (`role.view`) |
| Audit | `GET /orgs/{org_id}/audit-logs`, `GET /orgs/{org_id}/authz-decisions` (`audit_log.view`) |
| Health (unversioned, no middleware) | `GET /health`, `GET /health/live`, `GET /health/ready` |

Response envelopes (verified from `internal/response/`): success is
`{"success": true, "message": ..., "data": ...}`; errors are
`{"success": false, "error": {"code": ..., "message": ...}}`; validation failures add a
`fields` map keyed by Go struct field name. `request_id` is **not** in the body — it's
echoed in the `X-Request-ID` response header. 204 responses have no body.

## Testing and security verification

```bash
make test           # = go test ./...  (unit + integration)
go test ./internal/auth/...   # unit only: argon2id hashing + opaque-token contract
go test ./integration/...     # end-to-end against a real postgres:18 container
```

The integration suite (`integration/`) runs the **exact** handler + middleware stack
from `cmd/main.go` against a real PostgreSQL in Docker — no mocks, real SQL, real
migrations (applied with the simple query protocol, because pgx's default extended
protocol rejects multi-statement files). It skips
gracefully with a clear message if Docker is unavailable. Because the auth-route rate
limiter is keyed by IP and `ClientIP` prefers `X-Forwarded-For`, each test client spoofs
a unique XFF address, which isolates tests and makes the rate-limit test deterministic.

Security-specific tests worth knowing:

- `TestAuthRefresh_CSRFEnforcement` — double-submit CSRF on `/auth/refresh`
- `TestAuthRefresh_ReplayRevokesWholeFamily` — refresh rotation + reuse detection
- `TestIDOR_CrossOrgMemberDeleteIs404`, `TestNonMemberOrgAccess`,
  `TestCrossOrgIsolation_ListIsScopedToOrg` — tenant isolation / IDOR
- `TestLastOwnerCannotBeRemovedOrDemoted`, `TestOwnerActionRestricted`,
  `TestPersonalOrgInvariants` — owner invariants
- `TestLeaveOrg_AnyMemberCanLeaveAndOrgAccessIsRevoked`,
  `TestLeaveOrg_LastOwnerCannotLeave`, `TestLeaveOrg_NonMemberGets404` — the leave endpoint
- `TestRateLimiting_OrgRouteBurst`, `TestRateLimiting_IsKeyedPerIP` — rate limiting

**Threat model:** [THREAT_MODEL.md](THREAT_MODEL.md) — each of the four named threats,
the exact mitigation with file/function references, and a reproduction you can run.
**Security scan:** [SECURITY_SCAN.md](SECURITY_SCAN.md) — the report of the
security-verification pass: the four named threats manually verified (HELD), the
automated ZAP component blocked by environment network limits, and known defects
K1–K6 assessed by severity (K1–K5 fixed since the scan; K6 remains as a documented
accepted risk).

## What's deliberately not built

- **Role administration** — `role.create/update/delete` are seeded permissions but
  there are no endpoints to create/edit/delete custom roles; `GET /roles` is read-only.
- **Resource endpoints** — no resource API exists (see scope note at the top); the
  `resource.*` permissions and `authz_decisions.resource_type/resource_id` columns are
  placeholders for a future domain layer.
- **Password change / reset** — no such endpoints; credentials are only set at
  registration and checked at login.
- **A dedicated ownership-transfer endpoint** — there is no separate "transfer
  ownership" call; ownership changes are done by composing `AssignRole` (grant the
  owner role to someone else) with `Leave` or `Remove`. Members can leave an org on
  their own via `POST /orgs/{org_id}/leave`; the last owner cannot (`409 last_owner`).
  `ErrMustTransferOwnership` / `ErrOwnershipTransferInvalid` remain defined and mapped
  but no code path returns them.

## Known defects

Five defects found and pinned by the earlier test pass have been **fixed** in the
working tree (verified by source inspection; the suite now asserts the corrected
behavior):

1. **Registration without `last_name` → 500 — FIXED.** `users.last_name` is now
   nullable (`migrations/000001`) and an omitted `last_name` is stored as NULL, matching
   the request validation; registration returns 201.
   (`TestRegisterWithoutLastName_Succeeds`)
2. **Accepting a second invitation into an org you already belong to → 500 — FIXED.**
   `CreateMembership` now translates the memberships `UNIQUE(user_id, organization_id)`
   violation to `409 already_member`.
3. **Personal orgs accepting members — FIXED.** `Service.Invite` now blocks personal
   orgs with `409 personal_workspace` before any invitation row is created.
   (`TestPersonalOrgInvariants`)
4. **Non-owner demoting an owner — FIXED.** `AssignRole` now applies the owner-only
   restriction in **both** directions: granting *and* revoking owner status require an
   owner actor, so an admin demoting an owner gets `403 owner_action_restricted` (the
   last-owner guard, `409 last_owner`, still protects the org's final owner).
   (`TestOwnerActionRestricted`)
5. **Suspended-user login → 500 — FIXED.** `Login` returns `ErrUserSuspended` for any
   `status != 'active'` account; `response.HandleError` now maps it to
   `403 user_suspended`, so a suspended account gets a clear, distinct error instead of
   a generic 500. (`TestLogin_SuspendedUserReturns403`)

Still open (documented accepted risk):

6. **`X-Forwarded-For` trust.** Rate limiting keys on XFF; if this deploys behind a
   proxy, the proxy must overwrite (not append to) `X-Forwarded-For`, or the key is
   spoofable (`internal/utils/ipaddress.go` comment).

## Repository layout

```
cmd/                 entrypoint (wiring, middleware stack, graceful shutdown)
internal/
  auth/              register/login/refresh/logout, argon2id, opaque tokens, CSRF
  authz/             permission check + authz_decisions trail
  membership/        members, invitations, owner invariants
  organization/      org CRUD, bootstrap, personal/business types
  role/              read-only role catalog
  audit/             business-event audit log
  middleware/        recovery, request logger, security headers, CORS, authn, authz, rate limit
  routes/            the route table (every path and its middleware)
  response/          success/error envelopes, error-code → HTTP-status mapping
  requestctx/        user/org/session/request IDs on the request context
  validation/        struct validation + E.164/identifier rules
pkg/
  config/            env var loading + validation
  db/                pgxpool connect, Querier interface, query timeouts
migrations/          schema + seeds + org-provisioning trigger
integration/         end-to-end tests against real Postgres (Docker)
```

## Technology

Go 1.26.2 · PostgreSQL 18 · pgx/v5 · argon2id · Go 1.22+ pattern routing ·
`golang.org/x/time/rate` token buckets. See [go.mod](go.mod) for the complete list.
