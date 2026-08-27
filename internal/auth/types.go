package auth

import (
	"time"

	"github.com/google/uuid"
)

type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required,identifier"`
	Password   string `json:"password" validate:"required,min=4,max=72"`
}

type LoginResponse struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	User        UserInfo  `json:"user"`
}

type UserInfo struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Phone     string    `json:"phone"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name,omitempty"`
}
