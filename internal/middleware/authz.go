package middleware

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/authz"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/requestctx"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

// Authz enforces a single permission on a route, scoped to the org taken
// from the {org_id} route parameter.
//
// permissionKey is fixed per route registration, not derived at request
// time, e.g. Authz(repo, "member.invite") wraps the invite-member route
// specifically. Explicit per-route permissions are easier to audit than
// inferring the required permission from the HTTP method or path, and
// impossible to get subtly wrong by inference.
//
// Must run after Authn, it reads the user ID Authn set in the request
// context and does nothing to establish identity itself.
func Authz(repo *authz.Repository, permissionKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := requestctx.UserID(r.Context())
			if !ok {
				// Authn didn't run, or ran and failed to set identity,
				// either way this is a wiring bug, not a client error.
				response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
				return
			}

			orgID, err := uuid.Parse(r.PathValue("org_id"))
			if err != nil {
				response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
				return
			}

			allowed, err := repo.CheckPermission(r.Context(), userID, orgID, permissionKey)
			if err != nil {
				response.Error(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
				return
			}

			reason := "role lacks permission"
			if allowed {
				reason = "role grants permission"
			}

			// Recorded for every decision, allowed or denied — this is the
			// full audit trail, not just a denial log. A failure to write
			// it doesn't change the access decision itself; it's logged
			// and the request proceeds (or is denied) on its own merits.
			if err := repo.RecordDecision(r.Context(), authz.Decision{
				OrganizationID: orgID,
				UserID:         userID,
				PermissionKey:  permissionKey,
				Allowed:        allowed,
				Reason:         reason,
			}); err != nil {
				logger.Error("authz decision write failed", "err", err, "user_id", userID, "org_id", orgID)
			}

			if !allowed {
				response.Error(w, http.StatusForbidden, "forbidden", "You do not have permission to perform this action")
				return
			}

			ctx := requestctx.WithOrgID(r.Context(), orgID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
