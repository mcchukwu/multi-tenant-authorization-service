package auth

import (
	"encoding/json"
	"net/http"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/normalize"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/utils"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/validation"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
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

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Normalize phone number
	if req.Phone != "" {
		normalized, err := normalize.Phone(req.Phone, "")
		if err != nil {
			response.ValidationError(w, map[string]string{"phone": "must be a valid phone number"})
			return
		}
		req.Phone = normalized
	}

	// Normalize email
	if req.Email != "" {
		req.Email = normalize.Email(req.Email)
	}

	// Validate request
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
		// apperrors.ErrEmailTaken / ErrPhoneTaken need a case in
		// response.HandleError mapping to http.StatusConflict (409) —
		// add these alongside your existing error-to-status mapping.
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

	// Normalize if identifier
	req.Identifier = normalize.Identifier(req.Identifier, "NG")

	// Validate request
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

	// Access token: returned in the body, not a cookie — client holds it in
	// memory and sends it as `Authorization: Bearer <token>`. Never
	// auto-attached by the browser, so it carries no CSRF exposure at all.
	response.Success(w, http.StatusOK, "login successful", LoginResponse{
		AccessToken: result.AccessToken,
		ExpiresAt:   result.AccessTokenExpiresAt,
		User:        result.User,
	})
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	// CSRF check happens before touching the refresh token at all
	// no point validating a token if the request itself isn't trusted.
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
	})
}
