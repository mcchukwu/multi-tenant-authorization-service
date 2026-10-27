# Verification

Commands below are the ones that were run. If a claim is not covered here, treat it as unverified.

## Build and static checks

```bash
gofmt -l .          # no output
go vet ./...
go build ./...
```

## Tests

```bash
go test ./internal/...   # unit, no Docker
go test ./... -count=1   # unit + integration, starts postgres:18
MTAS_REQUIRE_DOCKER=1 go test ./... -count=1  # fails instead of skipping
```

The integration tier applies the migrations with `cmd/migrate`, starts the same middleware stack as `cmd/main.go`, and runs against a real database.

## End-to-end setup

```bash
cp .env.example .env
make bootstrap
make migrate        # second run reports "migrations up to date"
make run
curl -s localhost:6070/health/ready
```

## Threat coverage

| Claim | Test |
|---|---|
| Logout revokes the current session | `TestAuthLifecycle_RegisterLoginRefreshLogout` |
| Logout-all revokes every session | `TestAuthLogoutAll_RevokesEverySession` |
| Replaying a rotated refresh token revokes the family | `TestAuthRefresh_ReplayRevokesWholeFamily` |
| Concurrent refresh yields one token | `TestRefresh_ConcurrentReplayYieldsOneToken` |
| CSRF is required on refresh | `TestAuthRefresh_CSRFEnforcement` |
| The CSRF token is reachable from a browser client | `TestAuthResponsesExposeCSRFToken` |
| Cross-org member deletion is a 404 | `TestIDOR_CrossOrgMemberDeleteIs404` |
| Non-members cannot read an org | `TestNonMemberOrgAccess` |
| Member lists are scoped to the org | `TestCrossOrgIsolation_ListIsScopedToOrg` |
| The last owner cannot be removed or demoted | `TestLastOwnerCannotBeRemovedOrDemoted` |
| Only an owner can grant or revoke owner | `TestOwnerActionRestricted` |
| A deleted org is closed to its members | `TestDeletedOrganization_IsClosedToMembers` |
| Accounts without a last name can log in and be listed | `TestAccountsWithoutLastName_CanLoginAndBeListed` |
| Rate limiting is per IP and per org | `TestRateLimiting_IsKeyedPerIP`, `TestRateLimiting_OrgRouteBurst` |
| Oversized request bodies are rejected | `TestRequestBodyLimit` |

## Not verified here

- A container image was not built successfully in the development environment used for this pass; the registry pull timed out. The Dockerfile is unverified.
- No load test, penetration test or dependency scan was run.
- No backup or restore was exercised.
- TLS termination and proxy behaviour are deployment responsibilities and are not covered by these tests.
