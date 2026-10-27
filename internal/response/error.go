package response

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
)

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Success bool        `json:"success"`
	Error   ErrorDetail `json:"error"`
}

type ValidationErrorResponse struct {
	Success bool `json:"success"`
	Error   struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Fields  map[string]string `json:"fields"`
	} `json:"error"`
}

func Error(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(status)

	json.NewEncoder(w).Encode(ErrorResponse{
		Success: false,
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

func ValidationError(w http.ResponseWriter, fields map[string]string) {
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusBadRequest)

	json.NewEncoder(w).Encode(ValidationErrorResponse{
		Success: false,
		Error: struct {
			Code    string            `json:"code"`
			Message string            `json:"message"`
			Fields  map[string]string `json:"fields"`
		}{
			Code:    "validation_error",
			Message: "validation failed",
			Fields:  fields,
		},
	})
}

func HandleError(w http.ResponseWriter, err error) {
	switch {
	// AUTH
	case errors.Is(err, apperrors.ErrInvalidCredentials):
		Error(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
	case errors.Is(err, apperrors.ErrUnauthorized):
		Error(w, http.StatusUnauthorized, "unauthorized", "authentication required")
	case errors.Is(err, apperrors.ErrInvalidToken):
		Error(w, http.StatusUnauthorized, "invalid_token", "invalid token")

		// USERS
	case errors.Is(err, apperrors.ErrEmailAlreadyExists):
		Error(w, http.StatusConflict, "email_already_exists", "email already exists")
	case errors.Is(err, apperrors.ErrPhoneAlreadyExists):
		Error(w, http.StatusConflict, "phone_already_exists", "phone already exists")
	case errors.Is(err, apperrors.ErrUserSuspended):
		Error(w, http.StatusForbidden, "user_suspended", "user suspended")

	// ORGS
	case errors.Is(err, apperrors.ErrOrganizationNotFound):
		Error(w, http.StatusNotFound, "organization_not_found", "organization not found")
	case errors.Is(err, apperrors.ErrOrganizationIDInvalid):
		Error(w, http.StatusBadRequest, "invalid_organization_id", "organization id is invalid")
	case errors.Is(err, apperrors.ErrLastOwner):
		Error(w, http.StatusConflict, "last_owner", "last owner cannot be removed")
	case errors.Is(err, apperrors.ErrOwnerActionRestricted):
		Error(w, http.StatusForbidden, "owner_action_restricted", "owner action restricted")
	case errors.Is(err, apperrors.ErrCannotDeletePersonalOrg):
		Error(w, http.StatusConflict, "cannot_delete_personal_org", "cannot delete personal organization")

	// MEMBERSHIPS
	case errors.Is(err, apperrors.ErrMembershipNotFound):
		Error(w, http.StatusNotFound, "membership_not_found", "membership not found")
	case errors.Is(err, apperrors.ErrMembershipRoleNotFound):
		Error(w, http.StatusNotFound, "membership_not_found", "membership not found")
	case errors.Is(err, apperrors.ErrAlreadyMember):
		Error(w, http.StatusConflict, "already_member", "user already belongs to organization")
	case errors.Is(err, apperrors.ErrInvitationNotFound):
		Error(w, http.StatusNotFound, "invitation_not_found", "invitation not found")
	case errors.Is(err, apperrors.ErrPersonalWorkspace):
		Error(w, http.StatusConflict, "personal_workspace",
			"this is a personal workspace; create a new workspace to invite members")

	// VALIDATION
	case errors.Is(err, apperrors.ErrInvalidRequestBody):
		Error(w, http.StatusBadRequest, "invalid_request_body", "request body is invalid")
	case errors.Is(err, apperrors.ErrUserIdentifierInvalid):
		Error(w, http.StatusBadRequest, "invalid_identifier", "phone or email is invalid")

	// RATE LIMIT

	// METHOD / SYSTEM

	// DEFAULT
	default:
		Error(w, http.StatusInternalServerError, "internal_server_error", "internal server error")
	}
}
