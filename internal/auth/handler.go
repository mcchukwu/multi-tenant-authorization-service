package auth

import (
	"encoding/json"
	"net/http"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/logger"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/normalize"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/requestctx"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/utils"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/validation"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Phone != "" {
		normalized, err := normalize.Phone(req.Phone, "")
		if err != nil {
			response.ValidationError(w, map[string]string{"phone": "must be a valid phone number"})
			return
		}
		req.Phone = normalized
	}

	if req.Email != "" {
		req.Email = normalize.Email(req.Email)
	}

	if err := validation.ValidateStruct(req); err != nil {
		response.ValidationError(w, err)
		return
	}

	result, err := h.service.Register(r.Context(), RegisterInput{
		Email:     req.Email,
		Phone:     req.Phone,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		UserAgent: r.UserAgent(),
		IPAddress: utils.ClientIP(r),
	})
	if err != nil {
		response.HandleError(w, err)
		return
	}

	csrfToken, err := newCSRFToken()
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		logger.Error("failed to generate CSRF token", "err", err.Error())
		return
	}
	setAuthCookies(w, result.RefreshToken, csrfToken, result.RefreshTokenExpiresAt)

	response.Success(w, http.StatusCreated, "account created", RegisterResponse{
		AccessToken:  result.AccessToken,
		ExpiresAt:    result.AccessTokenExpiresAt,
		CSRFToken:    csrfToken,
		User:         result.User,
		Organization: result.Organization,
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	req.Identifier = normalize.Identifier(req.Identifier, "NG")

	if err := validation.ValidateStruct(req); err != nil {
		response.ValidationError(w, err)
		return
	}

	result, err := h.service.Login(r.Context(), LoginInput{
		Identifier: req.Identifier,
		Password:   req.Password,
		UserAgent:  r.UserAgent(),
		IPAddress:  utils.ClientIP(r),
	})
	if err != nil {
		response.HandleError(w, err)
		return
	}

	csrfToken, err := newCSRFToken()
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	setAuthCookies(w, result.RefreshToken, csrfToken, result.RefreshTokenExpiresAt)

	response.Success(w, http.StatusOK, "login successful", LoginResponse{
		AccessToken: result.AccessToken,
		ExpiresAt:   result.AccessTokenExpiresAt,
		CSRFToken:   csrfToken,
		User:        result.User,
	})
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Check CSRF before reading the refresh token.
	if !verifyCSRF(r) {
		response.Error(w, http.StatusForbidden, "csrf_check_failed", "CSRF validation failed")
		return
	}

	cookie, err := r.Cookie(refreshCookieName)
	if err != nil || cookie.Value == "" {
		response.Error(w, http.StatusUnauthorized, "missing_token", "Refresh token is required")
		return
	}

	result, err := h.service.Refresh(r.Context(), RefreshInput{
		RefreshToken: cookie.Value,
		UserAgent:    r.UserAgent(),
		IPAddress:    utils.ClientIP(r),
	})
	if err != nil {
		response.HandleError(w, err)
		return
	}

	csrfToken, err := newCSRFToken()
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	setAuthCookies(w, result.RefreshToken, csrfToken, result.RefreshTokenExpiresAt)

	response.Success(w, http.StatusOK, "token refreshed", RefreshResponse{
		AccessToken: result.AccessToken,
		ExpiresAt:   result.AccessTokenExpiresAt,
		CSRFToken:   csrfToken,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := requestctx.SessionID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}
	if err := h.service.Logout(r.Context(), sessionID); err != nil {
		response.HandleError(w, err)
		return
	}
	clearAuthCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := requestctx.UserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}
	if err := h.service.LogoutAll(r.Context(), userID); err != nil {
		response.HandleError(w, err)
		return
	}
	clearAuthCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := requestctx.UserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}
	// A missing session ID only means no row is marked current.
	currentSessionID, _ := requestctx.SessionID(r.Context())

	sessions, err := h.service.ListSessions(r.Context(), userID)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	out := make([]SessionResponse, len(sessions))
	for i, s := range sessions {
		out[i] = SessionResponse{
			ID:        s.ID.String(),
			UserAgent: s.UserAgent,
			IPAddress: s.IPAddress,
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
			Current:   s.ID == currentSessionID,
		}
	}
	response.Success(w, http.StatusOK, "sessions retrieved", out)
}
