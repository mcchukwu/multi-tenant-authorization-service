package authz

import (
	"time"

	"github.com/google/uuid"
)

type Decision struct {
	OrganizationID uuid.UUID
	UserID         uuid.UUID
	PermissionKey  string
	ResourceType   string // empty string stored as NULL
	ResourceID     *uuid.UUID
	Allowed        bool
	Reason         string
}

type DecisionView struct {
	ID            uuid.UUID  `json:"id"`
	UserID        *uuid.UUID `json:"user_id,omitempty"`
	PermissionKey string     `json:"permission_key"`
	ResourceType  *string    `json:"resource_type,omitempty"`
	ResourceID    *uuid.UUID `json:"resource_id,omitempty"`
	Allowed       bool       `json:"allowed"`
	Reason        string     `json:"reason"`
	CreatedAt     time.Time  `json:"created_at"`
}
