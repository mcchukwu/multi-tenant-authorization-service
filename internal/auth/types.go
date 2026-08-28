package auth

import (
	"time"

	"github.com/google/uuid"
)

// --

type RegisterRequest struct {
	Email     string `json:"email,omitempty" validate:"omitempty,email"`
	Phone     string `json:"phone,omitempty" validate:"omitempty,e164"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"omitempty"`
}

type RegisterResponse struct {
	AccessToken  string           `json:"access_token"`
	ExpiresAt    time.Time        `json:"expires_at"`
	User         UserInfo         `json:"user"`
	Organization OrganizationInfo `json:"organization"`
}

type OrganizationInfo struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Type string    `json:"type"`
}

// --

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

// --

type RefreshResponse struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}
