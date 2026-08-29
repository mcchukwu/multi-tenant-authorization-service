package organization

import (
	"time"

	"github.com/google/uuid"
)

type CreateOrgRequest struct {
	Name string `json:"name" validate:"required"`
}

type Organization struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Slug      *string   `json:"slug,omitempty"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UpdateOrgRequest struct {
	Name string `json:"name" validate:"required"`
}
