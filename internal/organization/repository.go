package organization

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
)

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

type Repository struct {
	db db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{db: q}
}

func (r *Repository) GetByID(ctx context.Context, orgID uuid.UUID) (*Organization, error) {
	const q = `
		SELECT id, name, type, slug, status, created_at, updated_at
		FROM organizations
		WHERE id = $1 AND status != 'deleted'
	`
	var o Organization
	err := r.db.QueryRow(ctx, q, orgID).Scan(
		&o.ID, &o.Name, &o.Type, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrOrganizationNotFound
		}
		return nil, apperrors.ErrDatabase
	}
	return &o, nil
}

func (r *Repository) UpdateName(ctx context.Context, orgID uuid.UUID, name string) (*Organization, error) {
	const q = `
		UPDATE organizations
		SET name = $1
		WHERE id = $2 AND status != 'deleted'
		RETURNING id, name, type, slug, status, created_at, updated_at
	`
	var o Organization
	err := r.db.QueryRow(ctx, q, name, orgID).Scan(
		&o.ID, &o.Name, &o.Type, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrOrganizationNotFound
		}
		return nil, apperrors.ErrDatabase
	}
	return &o, nil
}

// SoftDelete marks the org deleted rather than removing the row —
// organizations.status already models this (active/suspended/deleted),
// and a hard DELETE would cascade-orphan every audit_logs/authz_decisions
// row referencing it, destroying exactly the audit trail the CV bullet
// depends on.
func (r *Repository) SoftDelete(ctx context.Context, orgID uuid.UUID) error {
	const q = `UPDATE organizations SET status = 'deleted' WHERE id = $1 AND status != 'deleted'`
	tag, err := r.db.Exec(ctx, q, orgID)
	if err != nil {
		return apperrors.ErrDatabase
	}
	if tag.RowsAffected() == 0 {
		return apperrors.ErrOrganizationNotFound
	}
	return nil
}

func (r *Repository) Create(ctx context.Context, name, orgType string) (uuid.UUID, error) {
	const q = `INSERT INTO organizations (name, type) VALUES ($1, $2) RETURNING id`
	var id uuid.UUID
	if err := r.db.QueryRow(ctx, q, name, orgType).Scan(&id); err != nil {
		return uuid.Nil, apperrors.ErrDatabase
	}
	return id, nil
}

func (r *Repository) GetRoleIDByKind(ctx context.Context, orgID uuid.UUID, kind string) (uuid.UUID, error) {
	const q = `SELECT id FROM roles WHERE organization_id = $1 AND kind = $2`
	var id uuid.UUID
	if err := r.db.QueryRow(ctx, q, orgID, kind).Scan(&id); err != nil {
		return uuid.Nil, apperrors.ErrDatabase
	}
	return id, nil
}

func (r *Repository) AddOwnerMembership(ctx context.Context, orgID, userID, roleID uuid.UUID) error {
	const q = `
		INSERT INTO memberships (user_id, organization_id, role_id, status)
		VALUES ($1, $2, $3, 'active')
	`
	if _, err := r.db.Exec(ctx, q, userID, orgID, roleID); err != nil {
		return apperrors.ErrDatabase
	}
	return nil
}

// Bootstrap creates a new organization of the given type and assigns
// userID as its owner — org insert, owner-role lookup, and owner
// membership insert, as one unit. This is the single implementation of
// "stand up a new org with an owner," used both by registration (type
// "personal", composed inside auth's larger user+org+session
// transaction) and standalone org creation (type "business", its own
// transaction). Bootstrap doesn't start a transaction itself — callers
// compose it into whichever transaction they're already running via
// NewRepository(tx).
func (r *Repository) Bootstrap(ctx context.Context, name, orgType string, ownerUserID uuid.UUID) (uuid.UUID, error) {
	orgID, err := r.Create(ctx, name, orgType)
	if err != nil {
		return uuid.Nil, err
	}
	ownerRoleID, err := r.GetRoleIDByKind(ctx, orgID, "owner")
	if err != nil {
		return uuid.Nil, err
	}
	if err := r.AddOwnerMembership(ctx, orgID, ownerUserID, ownerRoleID); err != nil {
		return uuid.Nil, err
	}
	return orgID, nil
}
