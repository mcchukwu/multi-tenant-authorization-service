package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/audit"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/logger"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/organization"
)

type Service struct {
	repo   *Repository
	audit  *audit.Service
	cfg    *config.Config
	dbPool *pgxpool.Pool
}

func NewService(repo *Repository, audit *audit.Service, cfg *config.Config, pool *pgxpool.Pool) *Service {
	return &Service{
		repo:   repo,
		audit:  audit,
		cfg:    cfg,
		dbPool: pool,
	}
}

type RegisterInput struct {
	Email     string
	Phone     string
	Password  string
	FirstName string
	LastName  string
	UserAgent string
	IPAddress string
}

type RegisterResult struct {
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
	User                  UserInfo
	Organization          OrganizationInfo
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	if input.Email == "" && input.Phone == "" {
		return nil, apperrors.ErrUserIdentifierInvalid
	}

	// Hash before opening the transaction; argon2 is CPU work.
	passwordHash, err := HashPassword(input.Password)
	if err != nil {
		return nil, apperrors.ErrInternalServer
	}

	var (
		userID, orgID                     uuid.UUID
		orgName                           string
		rawAccess, rawRefresh             string
		accessExpiresAt, refreshExpiresAt time.Time
	)

	// User, personal org, membership and session are one unit.
	err = pgx.BeginFunc(ctx, s.dbPool, func(tx pgx.Tx) error {
		userRepo := NewRepository(tx)
		var err error

		userID, err = userRepo.CreateUser(ctx, NewUser{
			Email:        input.Email,
			Phone:        input.Phone,
			PasswordHash: passwordHash,
			FirstName:    input.FirstName,
			LastName:     input.LastName,
		})
		if err != nil {
			return err
		}

		orgRepo := organization.NewRepository(tx)

		orgName = fmt.Sprintf("%s's Workspace", input.FirstName)
		orgID, err = orgRepo.Bootstrap(ctx, orgName, "personal", userID)
		if err != nil {
			return err
		}

		var hashedAccess, hashedRefresh string
		rawAccess, hashedAccess, err = generateOpaqueToken()
		if err != nil {
			return apperrors.ErrInternalServer
		}
		rawRefresh, hashedRefresh, err = generateOpaqueToken()
		if err != nil {
			return apperrors.ErrInternalServer
		}

		now := time.Now()
		accessExpiresAt = now.Add(s.cfg.AccessTokenTTL)
		refreshExpiresAt = now.Add(s.cfg.RefreshTokenTTL)

		_, err = userRepo.CreateSession(ctx, &NewSession{
			UserID:                userID,
			RefreshTokenHash:      hashedRefresh,
			AccessTokenHash:       hashedAccess,
			UserAgent:             input.UserAgent,
			IPAddress:             input.IPAddress,
			AccessTokenExpiresAt:  accessExpiresAt,
			RefreshTokenExpiresAt: refreshExpiresAt,
		})
		return err
	})
	if err != nil {
		return nil, err
	}

	// Best effort, after commit: an audit failure must not fail signup.
	if auditErr := s.audit.Log(ctx, &audit.LogEntry{
		OrganizationID: &orgID,
		UserID:         &userID,
		Action:         "user.registered",
		EntityType:     "user",
		EntityID:       &userID,
		Metadata:       map[string]any{},
		IPAddress:      input.IPAddress,
		UserAgent:      input.UserAgent,
	}); auditErr != nil {
		logger.Error("audit log write failed", "err", auditErr, "user_id", userID)
	}

	return &RegisterResult{
		AccessToken:           rawAccess,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshToken:          rawRefresh,
		RefreshTokenExpiresAt: refreshExpiresAt,
		User: UserInfo{
			ID:        userID,
			Email:     input.Email,
			FirstName: input.FirstName,
			LastName:  input.LastName,
		},
		Organization: OrganizationInfo{
			ID:   orgID,
			Name: orgName,
			Type: "personal",
		},
	}, nil
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

	// Verify even when the user is missing, so response time does not
	// reveal whether the account exists.
	passwordToVerify := dummyHash
	if lookupErr == nil {
		passwordToVerify = user.PasswordHash
	}

	valid, verifyErr := VerifyPassword(passwordToVerify, input.Password)
	if verifyErr != nil {
		return nil, apperrors.ErrInternalServer
	}

	if lookupErr != nil || !valid {
		return nil, apperrors.ErrInvalidCredentials
	}

	if user.Status != "active" {
		return nil, apperrors.ErrUserSuspended
	}

	rawAccess, hashedAccess, err := generateOpaqueToken()
	if err != nil {
		return nil, apperrors.ErrInternalServer
	}
	rawRefresh, hashedRefresh, err := generateOpaqueToken()
	if err != nil {
		return nil, apperrors.ErrInternalServer
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
			Email:     user.Email.String,
			Phone:     user.Phone.String,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		},
	}, nil
}

type RefreshInput struct {
	RefreshToken string
	UserAgent    string
	IPAddress    string
}

type RefreshResult struct {
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

// errRefreshReplay never leaves the service: the transaction rolls back
// first, then the family is revoked.
var errRefreshReplay = errors.New("refresh token already rotated")

func (s *Service) Refresh(ctx context.Context, input RefreshInput) (*RefreshResult, error) {
	var (
		result   RefreshResult
		replayed *RefreshSessionRecord
	)

	// Row lock plus conditional revoke make rotation a compare-and-swap.
	err := pgx.BeginFunc(ctx, s.dbPool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)

		session, err := txRepo.GetSessionForRefresh(ctx, HashOpaqueToken(input.RefreshToken))
		if err != nil {
			return err
		}
		if session.Revoked {
			replayed = session
			return errRefreshReplay
		}
		if time.Now().After(session.RefreshTokenExpiresAt) {
			return apperrors.ErrInvalidToken
		}

		rawAccess, hashedAccess, err := generateOpaqueToken()
		if err != nil {
			return apperrors.ErrInternalServer
		}
		rawRefresh, hashedRefresh, err := generateOpaqueToken()
		if err != nil {
			return apperrors.ErrInternalServer
		}

		now := time.Now()
		accessExpiresAt := now.Add(s.cfg.AccessTokenTTL)
		refreshExpiresAt := now.Add(s.cfg.RefreshTokenTTL)

		revoked, err := txRepo.RevokeSessionIfActive(ctx, session.ID)
		if err != nil {
			return err
		}
		if !revoked {
			replayed = session
			return errRefreshReplay
		}

		if _, err := txRepo.CreateSessionInFamily(ctx, NewSessionInFamily{
			UserID:                session.UserID,
			TokenFamilyID:         session.TokenFamilyID,
			RefreshTokenHash:      hashedRefresh,
			AccessTokenHash:       hashedAccess,
			UserAgent:             input.UserAgent,
			IPAddress:             input.IPAddress,
			AccessTokenExpiresAt:  accessExpiresAt,
			RefreshTokenExpiresAt: refreshExpiresAt,
		}); err != nil {
			return err
		}

		result = RefreshResult{
			AccessToken:           rawAccess,
			AccessTokenExpiresAt:  accessExpiresAt,
			RefreshToken:          rawRefresh,
			RefreshTokenExpiresAt: refreshExpiresAt,
		}
		return nil
	})
	if errors.Is(err, errRefreshReplay) {
		s.revokeFamily(ctx, replayed, input)
		return nil, apperrors.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// revokeFamily treats reuse as theft and kills the whole lineage.
func (s *Service) revokeFamily(ctx context.Context, session *RefreshSessionRecord, input RefreshInput) {
	if err := s.repo.RevokeFamily(ctx, session.TokenFamilyID); err != nil {
		logger.Error("family revoke failed", "err", err, "family_id", session.TokenFamilyID)
	}

	if err := s.audit.Log(ctx, &audit.LogEntry{
		UserID:     &session.UserID,
		Action:     "token.replay_detected",
		EntityType: "session",
		EntityID:   &session.ID,
		Metadata:   map[string]any{"token_family_id": session.TokenFamilyID.String()},
		IPAddress:  input.IPAddress,
		UserAgent:  input.UserAgent,
	}); err != nil {
		logger.Error("audit log write failed", "err", err, "user_id", session.UserID)
	}
}

func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID) error {
	return s.repo.RevokeSession(ctx, sessionID)
}

func (s *Service) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	return s.repo.RevokeAllSessionsForUser(ctx, userID)
}

func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]SessionSummary, error) {
	return s.repo.ListActiveSessions(ctx, userID)
}
