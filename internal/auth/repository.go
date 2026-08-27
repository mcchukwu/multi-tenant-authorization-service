package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
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
		err = r.db.QueryRow(ctx, `
                SELECT id, password_hash, email, phone, first_name, last_name, status
								FROM users 
								WHERE email = $1
            `, identifier).Scan(&u.ID, &u.PasswordHash, u.Email, u.Phone, &u.FirstName, &u.LastName, &u.Status)
	} else {
		err = r.db.QueryRow(ctx, `
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
	err = r.db.QueryRow(ctx, q,
		s.UserID, s.RefreshTokenHash, s.AccessTokenHash,
		s.UserAgent, s.IPAddress,
		s.AccessTokenExpiresAt, s.RefreshTokenExpiresAt,
	).Scan(&sessionID)
	return sessionID, err
}
