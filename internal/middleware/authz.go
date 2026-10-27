package middleware

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/authz"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/logger"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/requestctx"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
)

// Authz checks one permission for the org in {org_id}. The permission is
// fixed at registration, never inferred from the method or path, and this
// must run after Authn.
func Authz(repo *authz.Repository, permissionKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := requestctx.UserID(r.Context())
			if !ok {
				// Missing identity here is a wiring bug, not a client error.
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

			// Every decision is recorded, allowed or denied. A failed
			// write is logged and does not change the outcome.
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
