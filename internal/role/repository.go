package role

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
)

type Role struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	IsSystem  bool      `json:"is_system"`
	CreatedAt time.Time `json:"created_at"`
}

type Repository struct {
	db db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{db: q}
}

func (r *Repository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]Role, error) {
	const q = `
		SELECT id, name, kind, is_system, created_at
		FROM roles
		WHERE organization_id = $1
		ORDER BY created_at ASC
	`
	rows, err := r.db.Query(ctx, q, orgID)
	if err != nil {
		return nil, apperrors.ErrDatabase
	}
	defer rows.Close()

	var out []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Kind, &role.IsSystem, &role.CreatedAt); err != nil {
			return nil, apperrors.ErrDatabase
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, apperrors.ErrDatabase
	}
	return out, nil
}

