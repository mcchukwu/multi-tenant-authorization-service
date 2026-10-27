package authz

import (
	"context"

	"github.com/google/uuid"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/db"
)

type Repository struct {
	db db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{db: q}
}

// CheckPermission joins membership, role and permission in one query.
func (r *Repository) CheckPermission(ctx context.Context, userID, orgID uuid.UUID, permissionKey string) (bool, error) {
	const q = `
		SELECT EXISTS (
			SELECT 1
			FROM memberships m
			JOIN organizations o ON o.id = m.organization_id AND o.status = 'active'
			JOIN role_permissions rp ON rp.role_id = m.role_id
			JOIN permissions p ON p.id = rp.permission_id
			WHERE m.user_id = $1
			  AND m.organization_id = $2
			  AND m.status = 'active'
			  AND p.key = $3
		)
	`
	var allowed bool
	if err := r.db.QueryRow(ctx, q, userID, orgID, permissionKey).Scan(&allowed); err != nil {
		return false, apperrors.ErrDatabase
	}
	return allowed, nil
}

// ListForOrg reads the decision trail for one org.
func (r *Repository) ListForOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]DecisionView, error) {
	const q = `
		SELECT id, user_id, permission_key, allowed, COALESCE(reason, ''), created_at
		FROM authz_decisions
		WHERE organization_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.db.Query(ctx, q, orgID, limit, offset)
	if err != nil {
		return nil, apperrors.ErrDatabase
	}
	defer rows.Close()

	var out []DecisionView
	for rows.Next() {
		var d DecisionView
		if err := rows.Scan(&d.ID, &d.UserID, &d.PermissionKey, &d.Allowed, &d.Reason, &d.CreatedAt); err != nil {
			return nil, apperrors.ErrDatabase
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, apperrors.ErrDatabase
	}
	return out, nil
}

// RecordDecision stores every check, allowed or denied.
func (r *Repository) RecordDecision(ctx context.Context, d Decision) error {
	const q = `
		INSERT INTO authz_decisions (
			organization_id, user_id, permission_key, allowed, reason
		) VALUES ($1, $2, $3, $4, $5)
	`
	_, err := r.db.Exec(ctx, q,
		d.OrganizationID, d.UserID, d.PermissionKey, d.Allowed, d.Reason,
	)
	if err != nil {
		return apperrors.ErrDatabase
	}
	return nil
}
