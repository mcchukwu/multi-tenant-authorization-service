package apperrors

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrInvalidToken       = errors.New("invalid token")

	ErrUserNotFound          = errors.New("user not found")
	ErrEmailAlreadyExists    = errors.New("email already exists")
	ErrPhoneAlreadyExists    = errors.New("phone already exists")
	ErrUserSuspended         = errors.New("user suspended")
	ErrUserIdentifierInvalid = errors.New("phone or email is invalid")

	ErrOrganizationIDInvalid   = errors.New("organization id is invalid")
	ErrOrganizationNotFound    = errors.New("organization not found")
	ErrCannotDeletePersonalOrg = errors.New("cannot delete personal organization")
	ErrLastOwner               = errors.New("last owner cannot be removed")
	ErrOwnerActionRestricted   = errors.New("owner action restricted")

	ErrMembershipNotFound     = errors.New("membership not found")
	ErrMembershipRoleNotFound = errors.New("membership role not found")
	ErrAlreadyMember          = errors.New("user already belongs to organization")
	ErrInvitationNotFound     = errors.New("invitation not found")
	ErrPersonalWorkspace      = errors.New("personal workspace does not accept staff members")

	ErrInvalidRequestBody = errors.New("invalid request body")
	ErrInternalServer     = errors.New("internal server error")
	ErrDatabase           = errors.New("database error")
)
