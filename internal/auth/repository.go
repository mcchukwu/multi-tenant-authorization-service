package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
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
// constraints on email/phone rather than a pre-check, a check then insert
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

type userRecord struct {
	ID           uuid.UUID
	PasswordHash string
	Email        pgtype.Text
	Phone        pgtype.Text
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
            `, identifier).Scan(&u.ID, &u.PasswordHash, &u.Email, &u.Phone, &u.FirstName, &u.LastName, &u.Status)
	} else {
		err = r.dbQuerier.QueryRow(ctx, `
                SELECT id, password_hash, email, phone, first_name, last_name, status
								FROM users 
								WHERE phone = $1
            `, identifier).Scan(&u.ID, &u.PasswordHash, &u.Email, &u.Phone, &u.FirstName, &u.LastName, &u.Status)
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
// lineage, the column's own DEFAULT gen_random_uuid() handles that, since
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
	if err != nil {
		return "", apperrors.ErrDatabase
	}

	return sessionID, nil
}

type SessionRecord struct {
	ID                   uuid.UUID
	UserID               uuid.UUID
	Revoked              bool
	AccessTokenExpiresAt time.Time
}

// GetActiveSessionByAccessTokenHash looks up a session by its access token
// hash and rejects anything that isn't currently valid, revoked or
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

type RefreshSessionRecord struct {
	ID                    uuid.UUID
	UserID                uuid.UUID
	TokenFamilyID         uuid.UUID
	Revoked               bool
	RefreshTokenExpiresAt time.Time
}

func (r *Repository) GetSessionByRefreshTokenHash(ctx context.Context, hash string) (*RefreshSessionRecord, error) {
	const q = `
		SELECT id, user_id, token_family_id, revoked, refresh_token_expires_at
		FROM sessions
		WHERE refresh_token_hash = $1
	`
	var s RefreshSessionRecord
	err := r.dbQuerier.QueryRow(ctx, q, hash).Scan(
		&s.ID, &s.UserID, &s.TokenFamilyID, &s.Revoked, &s.RefreshTokenExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrInvalidToken
		}
		return nil, apperrors.ErrDatabase
	}
	return &s, nil
}

func (r *Repository) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	const q = `UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE id = $1 AND revoked = false`
	if _, err := r.dbQuerier.Exec(ctx, q, sessionID); err != nil {
		return apperrors.ErrDatabase
	}
	return nil
}

// RevokeFamily kills every still-active session sharing a token_family_id.
// Called on reuse detection, the whole lineage is untrusted at that
// point, not just the one token that got replayed, so every session in it
// (including the legitimate client's current one) is forced to re-login.
func (r *Repository) RevokeFamily(ctx context.Context, familyID uuid.UUID) error {
	const q = `UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE token_family_id = $1 AND revoked = false`
	if _, err := r.dbQuerier.Exec(ctx, q, familyID); err != nil {
		return apperrors.ErrDatabase
	}
	return nil
}

type NewSessionInFamily struct {
	UserID                uuid.UUID
	TokenFamilyID         uuid.UUID // carried forward from the session being rotated — the reuse-detection lineage
	RefreshTokenHash      string
	AccessTokenHash       string
	UserAgent             string
	IPAddress             string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

// CreateSessionInFamily inserts a rotated session, explicitly passing the
// existing token_family_id, unlike CreateSession (login/register), which
// lets the column default start a fresh lineage. Kept as a separate
// method rather than an optional field on NewSession so the two intents
// (start a lineage vs continue one) can't be confused for each other.
func (r *Repository) CreateSessionInFamily(ctx context.Context, s NewSessionInFamily) (uuid.UUID, error) {
	const q = `
		INSERT INTO sessions (
			user_id, token_family_id, refresh_token_hash, access_token_hash,
			user_agent, ip_address, access_token_expires_at, refresh_token_expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`
	var id uuid.UUID
	err := r.dbQuerier.QueryRow(ctx, q,
		s.UserID, s.TokenFamilyID, s.RefreshTokenHash, s.AccessTokenHash,
		s.UserAgent, s.IPAddress, s.AccessTokenExpiresAt, s.RefreshTokenExpiresAt,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, apperrors.ErrDatabase
	}
	return id, nil
}

type SessionSummary struct {
	ID        uuid.UUID
	UserAgent string
	IPAddress string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (r *Repository) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]SessionSummary, error) {
	const q = `
		SELECT id, user_agent, ip_address, created_at, refresh_token_expires_at
		FROM sessions
		WHERE user_id = $1 AND revoked = false
		ORDER BY created_at DESC
	`
	rows, err := r.dbQuerier.Query(ctx, q, userID)
	if err != nil {
		return nil, apperrors.ErrDatabase
	}
	defer rows.Close()

	var out []SessionSummary
	for rows.Next() {
		var s SessionSummary
		if err := rows.Scan(&s.ID, &s.UserAgent, &s.IPAddress, &s.CreatedAt, &s.ExpiresAt); err != nil {
			return nil, apperrors.ErrDatabase
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, apperrors.ErrDatabase
	}
	return out, nil
}

func (r *Repository) RevokeAllSessionsForUser(ctx context.Context, userID uuid.UUID) error {
	const q = `UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE user_id = $1 AND revoked = false`
	if _, err := r.dbQuerier.Exec(ctx, q, userID); err != nil {
		return apperrors.ErrDatabase
	}
	return nil
}
