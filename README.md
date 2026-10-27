# Multi-tenant authorization service

A Go and PostgreSQL backend for organization-scoped roles, permissions, invitations and sessions. It is meant to be forked per product: one deployment per customer or app, renamed and extended with that domain's resources. It is not a shared identity provider.

What is implemented:

- Organizations with a personal workspace per user and business orgs on demand
- Roles (`owner`, `admin`, `member`, `viewer`) with a seeded permission catalog
- Link invitations with single-use acceptance and rotation
- Opaque access and refresh tokens, stored as SHA-256 hashes, with rotation and reuse detection
- Double-submit CSRF on the one cookie-authenticated route
- An authorization decision for every protected request, plus a business audit log
- Integration tests against a real PostgreSQL container through the production middleware stack

What is deliberately not here: OAuth/OIDC, SSO, MFA, email delivery, password reset, role administration, resource endpoints and account deletion. See [Limitations](#limitations) before adopting it.

## Quick start

Requires Go 1.26+ and Docker.

```bash
cp .env.example .env
make bootstrap   # starts PostgreSQL and applies migrations
make run         # serves on APP_PORT, 6070 by default
```

```bash
curl -s localhost:6070/health/ready
curl -s -X POST localhost:6070/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"Sup3rSecret!123","first_name":"Ada"}'
```

`make bootstrap` waits for the database health check before migrating. `make migrate` is safe to run again; applied files are recorded in `schema_migrations`.

## Configuration

Read from the environment, or from a `.env` file in the working directory. The process exits if a required value is missing or invalid.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `APP_NAME` | yes | | Any non-empty name |
| `APP_PORT` | yes | | HTTP listen port |
| `APP_ENV` | yes | | `development` or `production` |
| `DATABASE_URL` | yes | | `postgres://user:pass@host:port/db?sslmode=disable` |
| `ACCESS_TOKEN_TTL` | no | `15m` | Go duration |
| `REFRESH_TOKEN_TTL` | no | `720h` | Go duration |
| `CORS_ALLOWED_ORIGINS` | yes | | Comma-separated origins |

`compose.yaml` reads `DB_NAME`, `DB_USER`, `DB_PASSWORD` and `DB_PORT` to start the local database. The app does not read those.

Use a reverse proxy that terminates TLS and overwrites `X-Forwarded-For`; the rate limiter and audit log trust that header. The cookie flags assume HTTPS in production.

## Tests

```bash
make test        # unit + integration; the integration tier starts a postgres:18 container
go test ./internal/...   # unit only, no Docker
```

The integration suite applies the real migrations, boots the same handler and middleware stack as `cmd/main.go`, and skips when Docker is unavailable. Set `MTAS_REQUIRE_DOCKER=1` to turn that skip into a failure; CI does this.

`make fmt` lists unformatted files and `make vet` runs `go vet`.

## API

All routes are under `/v1` except health checks. Every non-auth route takes a bearer token. Org-scoped routes take `{org_id}` and check one fixed permission.

| Area | Endpoints |
|---|---|
| Auth | `POST /auth/register`, `/auth/login`, `/auth/refresh` (cookie + CSRF) |
| Sessions | `POST /auth/logout`, `/auth/logout-all`, `GET /auth/sessions` |
| Invitations | `POST /auth/invitations/{token}/accept` |
| Organizations | `POST /orgs`, `GET /me/organizations`, `GET/PATCH/DELETE /orgs/{org_id}` |
| Members | `GET /orgs/{org_id}/members`, `POST .../members/invite`, `DELETE .../members/{user_id}`, `PATCH .../members/{user_id}/role`, `POST .../invitations/{invitation_id}/rotate`, `POST .../leave` |
| Roles | `GET /orgs/{org_id}/roles` |
| Audit | `GET /orgs/{org_id}/audit-logs`, `GET /orgs/{org_id}/authz-decisions` |
| Health | `GET /health`, `/health/live`, `/health/ready` |

Successful responses are `{"success":true,"message":"...","data":...}`. Errors are `{"success":false,"error":{"code":"...","message":"..."}}`; validation errors add a `fields` map.

`POST /auth/refresh` needs the `refresh_token` and `csrf_token` cookies plus `X-CSRF-Token`. The CSRF cookie is scoped to `/v1/auth`, so a browser app served elsewhere should use the `csrf_token` returned in the register, login and refresh response bodies.

The OpenAPI description is in [openapi.yaml](openapi.yaml).

## Architecture

**Repositories over one querier.** Repositories take a `db.Querier`, satisfied by both `*pgxpool.Pool` and `pgx.Tx`, and never start transactions. Services compose them with `pgx.BeginFunc`, so multi-table operations are one unit: registration creates the user, personal org, owner membership and session together; invitation acceptance and refresh rotation are atomic.

**Tenant scoping in the query.** Org-scoped lookups filter on `(id, organization_id)`; a row from another tenant returns the same 404 as a missing one. Permission checks join `memberships`, `roles` and `permissions`, and require the organization to be active.

**Tokens.** Access and refresh tokens are 256-bit random values; only their SHA-256 hashes are stored. Refresh rotates in a transaction that locks the session row, and reusing a rotated token revokes the whole token family.

**Request path.** `Recovery -> RequestLogger -> SecurityHeaders -> CORS -> BodyLimit -> per-route RateLimiter -> Authn -> Authz -> handler`. `Authn` sets user and session IDs. `Authz` checks one permission per route and records the decision.

## Forking

See [FORKING.md](FORKING.md) for the rename checklist, where to add domain permissions, and how to keep a fork mergeable.

## Limitations

These are known and intentional for this baseline:

- **Fixed role catalog.** Read-only roles. Adding permissions means editing the seeds and, for a new role, the org provisioning function.
- **Link invitations only.** No email delivery, no invitee binding, no list or revoke endpoint.
- **No password reset or change, no email verification, no MFA.** A forgotten password needs database access.
- **No account deletion or data export.**
- **Rate limiting is per process and keyed by `X-Forwarded-For` or `{org_id}`.** Multiple replicas multiply the limit; a trusted proxy must overwrite the header.
- **No session or audit retention job.** `sessions` and `authz_decisions` grow until something deletes them.
- **Single database, no row-level security.** Isolation rests on the queries in the repository layer.
- **Audit writes are best effort.** A failed write is logged and the request continues.

Security decisions and their tests are in [THREAT_MODEL.md](THREAT_MODEL.md). Each claim there names the test that covers it.
