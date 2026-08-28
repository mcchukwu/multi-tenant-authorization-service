package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/utils"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
)

type Repository struct {
	dbQuerier db.Querier
}

func NewRepository(dbq db.Querier) *Repository {
	return &Repository{dbQuerier: dbq}
}

type NewUser struct {
	Email        string
	Phone        string
	PasswordHash string
	FirstName    string
	LastName     string
}

// CreateUser inserts a new user row. Relies on the database's UNIQUE
// constraints on email/phone rather than a pre-check, a check-then-insert
// pattern has a race window under concurrent registrations for the same
// email or phone; catching the constraint violation on insert doesn't.
func (r *Repository) CreateUser(ctx context.Context, u NewUser) (uuid.UUID, error) {
	const q = `
		INSERT INTO users (email, phone, password_hash, first_name, last_name)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`
	var id uuid.UUID
	err := r.dbQuerier.QueryRow(ctx, q, utils.NullableString(u.Email), utils.NullableString(u.Phone), u.PasswordHash, u.FirstName, utils.NullableString(u.LastName)).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			switch pgErr.ConstraintName {
			case "users_email_key":
				return uuid.Nil, apperrors.ErrEmailAlreadyExists
			case "users_phone_key":
				return uuid.Nil, apperrors.ErrPhoneAlreadyExists
			default:
				return uuid.Nil, apperrors.ErrDatabase
			}
		}
		return uuid.Nil, apperrors.ErrDatabase
	}
	return id, nil
}

// CreateOrganization inserts a new organization row. For a 'personal' org
// this fires the organizations_provision_roles trigger synchronously,
// within the same transaction — by the time this returns, the org already
// has its own cloned owner/admin/member/viewer roles.
func (r *Repository) CreateOrganization(ctx context.Context, name, orgType string) (uuid.UUID, error) {
	const q = `
		INSERT INTO organizations (name, type)
		VALUES ($1, $2)
		RETURNING id
	`
	var id uuid.UUID
	if err := r.dbQuerier.QueryRow(ctx, q, name, orgType).Scan(&id); err != nil {
		return uuid.Nil, apperrors.ErrDatabase
	}
	return id, nil
}

// GetRoleIDByKind looks up a role by its stable kind (not name) within a
// specific org — this is the kind column earning its keep: reliable even
// if the org later renames its roles.
func (r *Repository) GetRoleIDByKind(ctx context.Context, orgID uuid.UUID, kind string) (uuid.UUID, error) {
	const q = `SELECT id FROM roles WHERE organization_id = $1 AND kind = $2`
	var id uuid.UUID
	if err := r.dbQuerier.QueryRow(ctx, q, orgID, kind).Scan(&id); err != nil {
		return uuid.Nil, apperrors.ErrDatabase
	}
	return id, nil
}

// CreateMembership links a user to an org under a given role.
func (r *Repository) CreateMembership(ctx context.Context, userID, orgID, roleID uuid.UUID) error {
	const q = `
		INSERT INTO memberships (user_id, organization_id, role_id, status)
		VALUES ($1, $2, $3, 'active')
	`
	if _, err := r.dbQuerier.Exec(ctx, q, userID, orgID, roleID); err != nil {
		return apperrors.ErrDatabase
	}
	return nil
}

type userRecord struct {
	ID           uuid.UUID
	PasswordHash string
	Email        string
	Phone        string
	FirstName    string
	LastName     string
	Status       string
}

// GetUserByIdentifier looks up a user by email or phone. Returns ErrInvalidCredentials on no match
func (r *Repository) GetUserByIdentifier(ctx context.Context, identifier string) (*userRecord, error) {
	ctx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	var u userRecord
	var err error

	if strings.Contains(identifier, "@") {
		err = r.dbQuerier.QueryRow(ctx, `
                SELECT id, password_hash, email, phone, first_name, last_name, status
								FROM users 
								WHERE email = $1
            `, identifier).Scan(&u.ID, &u.PasswordHash, u.Email, u.Phone, &u.FirstName, &u.LastName, &u.Status)
	} else {
		err = r.dbQuerier.QueryRow(ctx, `
                SELECT id, password_hash, email, phone, first_name, last_name, status
								FROM users 
								WHERE phone = $1
            `, identifier).Scan(&u.ID, &u.PasswordHash, u.Email, u.Phone, &u.FirstName, &u.LastName, &u.Status)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrUserNotFound
		}

		return nil, apperrors.ErrDatabase
	}

	return &u, nil
}

type NewSession struct {
	UserID                uuid.UUID
	RefreshTokenHash      string
	AccessTokenHash       string
	UserAgent             string
	IPAddress             string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

// CreateSession inserts a new session row, starting a fresh token_family_id
// we never pass a family_id in on initial login. Rotation (in the future
// lineage — the column's own DEFAULT gen_random_uuid() handles that, since
// refresh handler) is the one place that must carry an existing family_id
// forward explicitly rather than letting a new one default in; that's what
// keeps the reuse-detection design intact.
func (r *Repository) CreateSession(ctx context.Context, s *NewSession) (sessionID string, err error) {
	ctx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	const q = `
		INSERT INTO sessions (
			user_id, refresh_token_hash, access_token_hash,
			user_agent, ip_address,
			access_token_expires_at, refresh_token_expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`
	err = r.dbQuerier.QueryRow(ctx, q,
		s.UserID, s.RefreshTokenHash, s.AccessTokenHash,
		s.UserAgent, s.IPAddress,
		s.AccessTokenExpiresAt, s.RefreshTokenExpiresAt,
	).Scan(&sessionID)
	return sessionID, err
}

type SessionRecord struct {
	ID                   uuid.UUID
	UserID               uuid.UUID
	Revoked              bool
	AccessTokenExpiresAt time.Time
}

// GetActiveSessionByAccessTokenHash looks up a session by its access token
// hash and rejects anything that isn't currently valid — revoked or
// expired sessions are treated identically to "no such token" so a caller
// can't distinguish "your token was fine but the session got revoked"
// from "that token never existed."
func (r *Repository) GetActiveSessionByAccessTokenHash(ctx context.Context, hash string) (*SessionRecord, error) {
	const q = `
		SELECT id, user_id, revoked, access_token_expires_at
		FROM sessions
		WHERE access_token_hash = $1
	`
	var s SessionRecord
	err := r.dbQuerier.QueryRow(ctx, q, hash).Scan(&s.ID, &s.UserID, &s.Revoked, &s.AccessTokenExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrInvalidToken
		}
		return nil, apperrors.ErrDatabase
	}
	if s.Revoked || time.Now().After(s.AccessTokenExpiresAt) {
		return nil, apperrors.ErrInvalidToken
	}
	return &s, nil
}
