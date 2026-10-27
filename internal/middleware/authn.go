package middleware

import (
	"net/http"
	"strings"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/auth"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/requestctx"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
)

// Authn sets the user and session IDs. Authz runs after it.
func Authn(repo *auth.Repository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				response.Error(w, http.StatusUnauthorized, "missing_token", "Authorization header with a bearer token is required")
				return
			}

			session, err := repo.GetActiveSessionByAccessTokenHash(r.Context(), auth.HashOpaqueToken(token))
			if err != nil {
				if err == apperrors.ErrInvalidToken {
					response.Error(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired session")
					return
				}
				response.Error(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
				return
			}

			ctx := requestctx.WithUserID(r.Context(), session.UserID)
			ctx = requestctx.WithSessionID(ctx, session.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken returns false for a missing or malformed header.
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if token == "" {
		return "", false
	}
	return token, true
}
