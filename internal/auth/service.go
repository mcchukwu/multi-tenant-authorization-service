package auth

import (
	"context"
	"errors"
	"time"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/audit"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

type Service struct {
	repo  *Repository
	audit *audit.Service
	cfg   *config.Config
}

func NewService(repo *Repository, audit *audit.Service, cfg *config.Config) *Service {
	return &Service{
		repo:  repo,
		audit: audit,
		cfg:   cfg,
	}
}

type LoginInput struct {
	Identifier string
	Password   string
	UserAgent  string
	IPAddress  string
}

type LoginResult struct {
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
	User                  UserInfo
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {

	user, lookupErr := s.repo.GetUserByIdentifier(ctx, input.Identifier)
	if lookupErr != nil && !errors.Is(lookupErr, apperrors.ErrUserNotFound) {
		return nil, lookupErr
	}

	// Always run verification, even when the user doesn't exist, against
	// the precomputed dummy hash in that case. This is what actually
	// prevents email enumeration: returning the same error message alone
	// doesn't help if one code path is measurably faster than the other,
	// and skipping verification entirely on "no such user" is exactly
	// that kind of timing gap.
	passwordToVerify := dummyHash
	if lookupErr == nil {
		passwordToVerify = user.PasswordHash
	}

	valid, verifyErr := VerifyPassword(passwordToVerify, input.Password)
	if verifyErr != nil {
		return nil, verifyErr
	}

	if lookupErr != nil || !valid {
		return nil, apperrors.ErrInvalidCredentials
	}

	if user.Status != "active" {
		return nil, apperrors.ErrUserSuspended
	}

	rawAccess, hashedAccess, err := generateOpaqueToken()
	if err != nil {
		return nil, err
	}
	rawRefresh, hashedRefresh, err := generateOpaqueToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	accessExpiresAt := now.Add(s.cfg.AccessTokenTTL)
	refreshExpiresAt := now.Add(s.cfg.RefreshTokenTTL)

	sessionEntry := &NewSession{
		UserID:                user.ID,
		RefreshTokenHash:      hashedRefresh,
		AccessTokenHash:       hashedAccess,
		UserAgent:             input.UserAgent,
		IPAddress:             input.IPAddress,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}

	if _, err := s.repo.CreateSession(ctx, sessionEntry); err != nil {
		return nil, err
	}

	auditEntry := &audit.LogEntry{
		UserID:     &user.ID,
		Action:     "user.logged_in",
		EntityType: "user",
		EntityID:   &user.ID,
		Metadata:   map[string]any{},
		IPAddress:  input.IPAddress,
		UserAgent:  input.UserAgent,
	}

	if auditErr := s.audit.Log(ctx, auditEntry); auditErr != nil {
		logger.Error("audit log write failed", "err", auditErr, "user_id", user.ID)
	}

	return &LoginResult{
		AccessToken:           rawAccess,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshToken:          rawRefresh,
		RefreshTokenExpiresAt: refreshExpiresAt,
		User: UserInfo{
			ID:        user.ID,
			Email:     user.Email,
			Phone:     user.Phone,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		},
	}, nil
}
