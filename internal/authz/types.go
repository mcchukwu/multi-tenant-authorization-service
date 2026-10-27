package authz

import (
	"time"

	"github.com/google/uuid"
)

type Decision struct {
	OrganizationID uuid.UUID
	UserID         uuid.UUID
	PermissionKey  string
	Allowed        bool
	Reason         string
}

type DecisionView struct {
	ID            uuid.UUID  `json:"id"`
	UserID        *uuid.UUID `json:"user_id,omitempty"`
	PermissionKey string     `json:"permission_key"`
	Allowed       bool       `json:"allowed"`
	Reason        string     `json:"reason"`
	CreatedAt     time.Time  `json:"created_at"`
}
