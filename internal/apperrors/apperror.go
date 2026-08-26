package apperrors

import "errors"

var (
	// AUTHENTICATION
	ErrInvalidCredentials = errors.New("invalid credentials")

	ErrUnauthorized = errors.New("unauthorized")

	ErrInvalidToken = errors.New("invalid token")

	ErrExpiredToken = errors.New("expired token")

	ErrSessionExpired = errors.New("session expired")

	ErrSessionRevoked = errors.New("session revoked")

	ErrMissingAuthorizationHeader = errors.New("missing authorization header")

	ErrInvalidAuthorizationHeader = errors.New("invalid authorization header")

	ErrInvalidPassword = errors.New("invalid password")

	// AUTHORIZATION
	ErrForbidden = errors.New("forbidden")

	ErrInsufficientPermissions = errors.New("insufficient permissions")

	// USERS
	ErrUserNotFound = errors.New("user not found")

	ErrEmailAlreadyExists = errors.New("email already exists")

	ErrPhoneAlreadyExists = errors.New("phone already exists")

	ErrPhoneNotVerified = errors.New("phone not verified")

	ErrUserSuspended = errors.New("user suspended")

	ErrUserIdentifierInvalid = errors.New("phone or email is invalid")

	// ORGANIZATIONS
	ErrOrganizationIDInvalid = errors.New("organization id is invalid")

	ErrOrganizationNotFound = errors.New("organization not found")

	ErrOrganizationSuspended = errors.New("organization suspended")

	ErrOrganizationDeleted = errors.New("organization deleted")

	ErrOrganizationSlugExists = errors.New("organization slug already exists")

	ErrOrganizationNameInvalid = errors.New("organization name is invalid")

	// ErrInviteNotFound is the COLLAPSED 404 for the public invite lookup and
	// accept flows: disabled/unknown/deleted/suspended/personal all resolve
	// to this single code (anti-enumeration). Also returned by PATCH invite
	// when no invite row exists.
	ErrInviteNotFound = errors.New("invite not found")

	// ErrMustTransferOwnership is returned when an owner tries to leave a
	// workspace without transferring ownership first (covers sole owners,
	// co-owners, and personal workspaces — the sole-owner rule is the
	// personal guard here). Maps to 409.
	ErrMustTransferOwnership = errors.New("must transfer ownership before leaving")

	// ErrOwnershipTransferInvalid is returned when the ownership-transfer
	// target cannot receive ownership (not a member, not active, or holds
	// the client/owner role). Maps to 409.
	ErrOwnershipTransferInvalid = errors.New("ownership transfer target is invalid")

	// MEMBERSHIPS
	ErrMembershipNotFound = errors.New("membership not found")

	ErrMembershipRoleNotFound = errors.New("membership role not found")

	ErrAlreadyMember = errors.New("user already belongs to organization")

	ErrInvitationPending = errors.New("invitation already pending")

	// ErrPersonalWorkspace is returned by staff-membership mutations on a
	// registration-created personal workspace. It maps to 409 Conflict (the
	// actor isn't lacking permission — even the owner is blocked), NOT 403.
	ErrPersonalWorkspace = errors.New("personal workspace does not accept staff members")

	// VALIDATION
	ErrValidation = errors.New("validation error")

	ErrInvalidRequestBody = errors.New("invalid request body")

	ErrMissingRequiredField = errors.New("missing required field")

	ErrInvalidEmail = errors.New("invalid email")

	ErrInvalidStatusTransition = errors.New("invalid status transition")

	ErrWeakPassword = errors.New("weak password")

	// RATE LIMITING
	ErrRateLimited = errors.New("too many requests")

	// SYSTEM
	ErrInternalServer   = errors.New("internal server error")
	ErrMethodNotAllowed = errors.New("method not allowed")

	ErrDatabase = errors.New("database error")
)

