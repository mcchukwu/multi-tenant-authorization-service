package membership

import (
	"time"

	"github.com/google/uuid"
)

type InviteRequest struct {
	RoleID string `json:"role_id" validate:"required,uuid"`
}

type InviteResponse struct {
	Token     string    `json:"token"`
	RoleID    string    `json:"role_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AssignRoleRequest struct {
	RoleID string `json:"role_id" validate:"required,uuid"`
}

type Member struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	RoleID    uuid.UUID `json:"role_id"`
	RoleName  string    `json:"role_name"`
	RoleKind  string    `json:"role_kind"`
	Status    string    `json:"status"`
	JoinedAt  time.Time `json:"joined_at"`
}

type Invitation struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	RoleID         uuid.UUID
	Status         string
	ExpiresAt      time.Time
}
