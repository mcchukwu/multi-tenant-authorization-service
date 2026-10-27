# Forking this service

One deployment per product is the intended model. Rename the module, add the permissions the product actually needs, and keep the core small enough to merge upstream changes.

## Rename checklist

1. Change the module path in `go.mod` and the import prefix in every Go file.
2. Change `APP_NAME` and the image name in `Makefile` and `Dockerfile`.
3. Replace the service name and repository URLs in this file and `README.md`.
4. Keep `migrations/` append-only. Never edit a migration that has run in an environment; add the next numbered file.

## Add domain permissions

Permissions are seeded in `migrations/000002_seed_permissions.up.sql`. Add keys for the product's resources, for example:

```sql
('student.view',   'View a student record'),
('student.update', 'Edit a student record'),
('shipment.dispatch', 'Dispatch a shipment')
```

Grant them to the template roles in `000003_seed_template_roles.up.sql`. Template roles are cloned into each organization when it is created, so a fork that changes the grants should also decide what happens to existing organizations: a data migration is usually cheaper than changing the provisioning function.

## Add resource endpoints

The core has no resource model beyond organizations. Add one in a new package:

- `internal/student/{handler,service,repository,types}.go`
- Register the routes in `internal/routes/routes.go` with the permission each route needs
- Take `{org_id}` from the path and pass it to every query; never accept a bare resource ID without the org predicate
- Use a composite foreign key like `memberships` does if the resource must belong to the same organization as its parent

The permission check happens in middleware. The service layer owns rules a permission cannot express, such as "an owner cannot be removed by an admin".

## Keep merges cheap

- Do not edit files under `internal/auth`, `internal/authz` or `internal/middleware` for product reasons.
- Put product code in new packages and new migrations.
- Keep `cmd/main.go` as wiring only.
- If a change belongs in the baseline, send it upstream instead of carrying it in the fork.

## What to change first in production

1. Set `CORS_ALLOWED_ORIGINS` to the real frontend origins.
2. Put the service behind TLS and a proxy that overwrites `X-Forwarded-For`.
3. Replace the link-invite flow if the product needs email invitations.
4. Add a retention job for `sessions` and `authz_decisions`.
5. Add the password reset and email verification flows the product needs.
6. Add a second replica only after moving rate limiting to a shared store.
