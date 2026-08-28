package authz

import (
	"context"

	"github.com/google/uuid"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/utils"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
)

type Repository struct {
	db db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{db: q}
}

// CheckPermission answers one question: does this user, in this org, hold
// a role granting this permission. One query, one round trip, joins
// straight from an active membership through its role to the permission
// key, rather than fetching the role first and checking separately, which
// would cost two queries for no benefit.
func (r *Repository) CheckPermission(ctx context.Context, userID, orgID uuid.UUID, permissionKey string) (bool, error) {
	const q = `
		SELECT EXISTS (
			SELECT 1
			FROM memberships m
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

type Decision struct {
	OrganizationID uuid.UUID
	UserID         uuid.UUID
	PermissionKey  string
	ResourceType   string // empty string stored as NULL
	ResourceID     *uuid.UUID
	Allowed        bool
	Reason         string
}

// RecordDecision writes every authorization check — allowed or denied —
// to authz_decisions. This is the audit trail the CV bullet actually
// means: not just "who got denied," but a complete record of every
// access decision the system made, so a security review can answer
// "what could user X do, and when did that access get exercised" after
// the fact.
func (r *Repository) RecordDecision(ctx context.Context, d Decision) error {
	const q = `
		INSERT INTO authz_decisions (
			organization_id, user_id, permission_key,
			resource_type, resource_id, allowed, reason
		) VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7)
	`
	_, err := r.db.Exec(ctx, q,
		d.OrganizationID, d.UserID, d.PermissionKey,
		utils.NullableString(d.ResourceType), d.ResourceID, d.Allowed, d.Reason,
	)
	if err != nil {
		return apperrors.ErrDatabase
	}
	return nil
}

