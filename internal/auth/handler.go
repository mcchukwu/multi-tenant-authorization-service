package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/normalize"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/validation"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/config"
)

type Handler struct {
	service *Service
	cfg     *config.Config
}

func NewHandler(service *Service, cfg *config.Config) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Normalize if identifier
	req.Identifier = normalize.Identifier(req.Identifier, "")

	if err := validation.ValidateStruct(req); err != nil {
		response.ValidationError(w, err)
		return
	}

	result, err := h.service.Login(r.Context(), LoginInput{
		Identifier: req.Identifier,
		Password:   req.Password,
		UserAgent:  r.UserAgent(),
		IPAddress:  clientIP(r),
	})
	if err != nil {
		response.HandleError(w, err)
		return
	}

	// Refresh token: httpOnly + Secure + SameSite=Strict cookie, scoped to
	// the auth routes only. Because this IS a cookie, the refresh endpoint
	// remains a CSRF target — SameSite=Strict narrows that, it doesn't
	// close it alone, so the refresh handler needs its own explicit CSRF
	// check when we build it next.
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    result.RefreshToken,
		Path:     "/v1/auth",
		HttpOnly: true,
		Secure:   h.cfg.AppEnv == "production",
		SameSite: http.SameSiteStrictMode,
		Expires:  result.RefreshTokenExpiresAt,
	})

	// Access token: returned in the body, not a cookie — client holds it in
	// memory and sends it as `Authorization: Bearer <token>`. Never
	// auto-attached by the browser, so it carries no CSRF exposure at all.
	response.Success(w, http.StatusOK, "login successful", LoginResponse{
		AccessToken: result.AccessToken,
		ExpiresAt:   result.AccessTokenExpiresAt,
		User:        result.User,
	})
}

// clientIP prefers X-Forwarded-For (set by a reverse proxy/load balancer)
// over RemoteAddr, since RemoteAddr is the proxy's own address once you're
// behind one. XFF is itself spoofable by the client unless your proxy is
// configured to overwrite rather than append to it — confirm that's true
// of your deployment before relying on this for anything security-critical
// like the per-tenant rate limiting you've got planned.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
