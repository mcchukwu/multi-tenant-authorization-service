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
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/organization"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
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

	// Hashing is pure CPU work — no reason to hold it inside the DB
	// transaction and extend how long any locks are held.
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

	// User, personal org, owner membership, and session must succeed or
	// fail together — an org with no owner membership, or a user with no
	// session, are both broken states nothing downstream expects to see.
	//
	// Transaction composition lives here, at the service layer, not on
	// Repository — the service is what knows it needs multiple domain
	// repositories (auth, and later others) inside one atomic unit.
	// pgx.Tx already satisfies db.Querier structurally, so no wrapper
	// type is needed to hand it to NewRepository.
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

	// Best-effort, run only after the transaction has committed — an audit
	// write failing here shouldn't roll back a successful registration,
	// matching the call you made on Login.
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

// Refresh is the second half of the refresh-token flow. It's a separate
// method so the caller can't accidentally reuse a refresh token to get
// another access token, which would be a security hole.
func (s *Service) Refresh(ctx context.Context, input RefreshInput) (*RefreshResult, error) {
	session, err := s.repo.GetSessionByRefreshTokenHash(ctx, HashOpaqueToken(input.RefreshToken))
	if err != nil {
		return nil, err
	}

	if session.Revoked {
		// This token was already rotated away, presenting it now means
		// either it leaked and an attacker is using a stale copy, or the
		// legitimate client retried a request whose response it never
		// saw. Either way, the whole lineage is no longer trustworthy:
		// revoke every session in the family, not just this one request.
		if revokeErr := s.repo.RevokeFamily(ctx, session.TokenFamilyID); revokeErr != nil {
			logger.Error("family revoke failed", "err", revokeErr, "family_id", session.TokenFamilyID)
		}

		if auditErr := s.audit.Log(ctx, &audit.LogEntry{
			UserID:     &session.UserID,
			Action:     "token.replay_detected",
			EntityType: "session",
			EntityID:   &session.ID,
			Metadata:   map[string]any{"token_family_id": session.TokenFamilyID.String()},
			IPAddress:  input.IPAddress,
			UserAgent:  input.UserAgent,
		}); auditErr != nil {
			logger.Error("audit log write failed", "err", auditErr, "user_id", session.UserID)
		}
		return nil, apperrors.ErrInvalidToken
	}

	if time.Now().After(session.RefreshTokenExpiresAt) {
		return nil, apperrors.ErrInvalidToken
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

	// Revoke-old + insert-new must be atomic, if the revoke succeeds but
	// the insert fails, the client is left with no valid refresh token at
	// all and no way to recover except a fresh login.
	err = pgx.BeginFunc(ctx, s.dbPool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)

		if err := txRepo.RevokeSession(ctx, session.ID); err != nil {
			return err
		}

		_, err := txRepo.CreateSessionInFamily(ctx, NewSessionInFamily{
			UserID:                session.UserID,
			TokenFamilyID:         session.TokenFamilyID,
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

	return &RefreshResult{
		AccessToken:           rawAccess,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshToken:          rawRefresh,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}, nil
}

// Logout revokes exactly the session the caller is currently
// authenticated with, RevokeSession already exists (built for refresh
// rotation).
func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID) error {
	return s.repo.RevokeSession(ctx, sessionID)
}

func (s *Service) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	return s.repo.RevokeAllSessionsForUser(ctx, userID)
}

func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]SessionSummary, error) {
	return s.repo.ListActiveSessions(ctx, userID)
}
