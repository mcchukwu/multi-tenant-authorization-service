package organization

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/db"
)

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

// SoftDelete also revokes outstanding invitations. A hard delete would
// take the audit rows with it.
func (r *Repository) SoftDelete(ctx context.Context, orgID uuid.UUID) error {
	const q = `
		WITH revoked AS (
			UPDATE invitations
			SET status = 'revoked'
			WHERE organization_id = $1 AND status = 'active'
		)
		UPDATE organizations SET status = 'deleted' WHERE id = $1 AND status = 'active'
	`
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

// ListForUser is the one cross-tenant query in this package; it starts
// from the caller's memberships.
func (r *Repository) ListForUser(ctx context.Context, userID uuid.UUID) ([]Organization, error) {
	const q = `
		SELECT o.id, o.name, o.type, o.slug, o.status, o.created_at, o.updated_at
		FROM organizations o
		JOIN memberships m ON m.organization_id = o.id
		WHERE m.user_id = $1 AND m.status = 'active' AND o.status != 'deleted'
		ORDER BY o.created_at ASC
	`
	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, apperrors.ErrDatabase
	}
	defer rows.Close()

	var out []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Type, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, apperrors.ErrDatabase
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, apperrors.ErrDatabase
	}
	return out, nil
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

// Bootstrap inserts the org, finds its owner role and adds the owner
// membership. It does not start a transaction; callers compose it.
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
