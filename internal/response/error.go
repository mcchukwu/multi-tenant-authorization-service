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
	case errors.Is(err, apperrors.ErrForbidden):
		Error(w, http.StatusForbidden, "forbidden", "access denied")
	case errors.Is(err, apperrors.ErrSessionExpired):
		Error(w, http.StatusUnauthorized, "session_expired", "session expired")
	case errors.Is(err, apperrors.ErrSessionRevoked):
		Error(w, http.StatusUnauthorized, "session_revoked", "session revoked")
	case errors.Is(err, apperrors.ErrInvalidToken):
		Error(w, http.StatusUnauthorized, "invalid_token", "invalid token")
	case errors.Is(err, apperrors.ErrInvalidPassword):
		Error(w, http.StatusUnauthorized, "invalid_password", "invalid password")
	case errors.Is(err, apperrors.ErrWeakPassword):
		Error(w, http.StatusBadRequest, "weak_password", "weak password")
	case errors.Is(err, apperrors.ErrInsufficientPermissions):
		Error(w, http.StatusForbidden, "insufficient_permissions", "insufficient permissions")

		// USERS
	case errors.Is(err, apperrors.ErrUserNotFound):
		Error(w, http.StatusConflict, "user_not_found", "user not found")
	case errors.Is(err, apperrors.ErrEmailAlreadyExists):
		Error(w, http.StatusConflict, "email_already_exists", "email already exists")
	case errors.Is(err, apperrors.ErrPhoneAlreadyExists):
		Error(w, http.StatusConflict, "phone_already_exists", "phone already exists")
	case errors.Is(err, apperrors.ErrUserSuspended):
		Error(w, http.StatusForbidden, "user_suspended", "user suspended")

	// ORGS
	case errors.Is(err, apperrors.ErrOrganizationNotFound):
		Error(w, http.StatusNotFound, "organization_not_found", "organization not found")
	case errors.Is(err, apperrors.ErrOrganizationSuspended):
		Error(w, http.StatusForbidden, "organization_suspended", "organization suspended")
	case errors.Is(err, apperrors.ErrOrganizationIDInvalid):
		Error(w, http.StatusBadRequest, "invalid_organization_id", "organization id is invalid")
	case errors.Is(err, apperrors.ErrOrganizationSlugExists):
		Error(w, http.StatusConflict, "organization_slug_exists", "organization slug already exists")
	case errors.Is(err, apperrors.ErrInviteNotFound):
		Error(w, http.StatusNotFound, "invite_not_found", "invite not found")
	case errors.Is(err, apperrors.ErrMustTransferOwnership):
		Error(w, http.StatusConflict, "must_transfer_ownership", "transfer ownership before leaving this workspace")
	case errors.Is(err, apperrors.ErrLastOwner):
		Error(w, http.StatusConflict, "last_owner", "last owner cannot be removed")
	case errors.Is(err, apperrors.ErrOwnerActionRestricted):
		Error(w, http.StatusForbidden, "owner_action_restricted", "owner action restricted")
	case errors.Is(err, apperrors.ErrOwnershipTransferInvalid):
		Error(w, http.StatusConflict, "ownership_transfer_invalid", "the selected member cannot receive ownership")
	case errors.Is(err, apperrors.ErrCannotDeletePersonalOrg):
		Error(w, http.StatusConflict, "cannot_delete_personal_org", "cannot delete personal organization")

	// MEMBERSHIPS
	case errors.Is(err, apperrors.ErrMembershipNotFound):
		Error(w, http.StatusNotFound, "membership_not_found", "membership not found")
	case errors.Is(err, apperrors.ErrMembershipRoleNotFound):
		Error(w, http.StatusNotFound, "membership_not_found", "membership not found")
	case errors.Is(err, apperrors.ErrAlreadyMember):
		Error(w, http.StatusConflict, "already_member", "user already belongs to organization")
	case errors.Is(err, apperrors.ErrInvitationPending):
		Error(w, http.StatusConflict, "invitation_pending", "invitation already pending")
	case errors.Is(err, apperrors.ErrInvitationNotFound):
		Error(w, http.StatusNotFound, "invitation_not_found", "invitation not found")
	case errors.Is(err, apperrors.ErrPersonalWorkspace):
		Error(w, http.StatusConflict, "personal_workspace",
			"this is a personal workspace; create a new workspace to invite members")

	// VALIDATION
	case errors.Is(err, apperrors.ErrValidation):
		Error(w, http.StatusBadRequest, "validation_error", "validation failed")
	case errors.Is(err, apperrors.ErrInvalidRequestBody):
		Error(w, http.StatusBadRequest, "invalid_request_body", "request body is invalid")
	case errors.Is(err, apperrors.ErrUserIdentifierInvalid):
		Error(w, http.StatusBadRequest, "invalid_identifier", "phone or email is invalid")

	// RATE LIMIT
	case errors.Is(err, apperrors.ErrRateLimited):
		Error(w, http.StatusTooManyRequests, "rate_limited", "too many requests")

	// METHOD / SYSTEM
	case errors.Is(err, apperrors.ErrMethodNotAllowed):
		Error(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")

	// DEFAULT
	default:
		Error(w, http.StatusInternalServerError, "internal_server_error", "internal server error")
	}
}
