package membership

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
)

type Repository struct {
	db db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{db: q}
}

func (r *Repository) ListMembers(ctx context.Context, orgID uuid.UUID) ([]Member, error) {
	const q = `
		SELECT u.id, u.email, u.first_name, u.last_name,
		       r.id, r.name, r.kind, m.status, m.joined_at
		FROM memberships m
		JOIN users u ON u.id = m.user_id
		JOIN roles r ON r.id = m.role_id
		WHERE m.organization_id = $1
		ORDER BY m.joined_at ASC
	`
	rows, err := r.db.Query(ctx, q, orgID)
	if err != nil {
		return nil, apperrors.ErrDatabase
	}
	defer rows.Close()

	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.FirstName, &m.LastName, &m.RoleID, &m.RoleName, &m.RoleKind, &m.Status, &m.JoinedAt); err != nil {
			return nil, apperrors.ErrDatabase
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, apperrors.ErrDatabase
	}
	return out, nil
}

// GetMemberRoleKind returns a member's role kind, used to enforce the
// owner-specific business rules that sit above the generic permission
// check: only an owner can grant the owner role, and the last owner
// can't be removed or demoted.
func (r *Repository) GetMemberRoleKind(ctx context.Context, orgID, userID uuid.UUID) (string, error) {
	const q = `
		SELECT rl.kind
		FROM memberships m
		JOIN roles rl ON rl.id = m.role_id
		WHERE m.organization_id = $1 AND m.user_id = $2 AND m.status = 'active'
	`
	var kind string
	err := r.db.QueryRow(ctx, q, orgID, userID).Scan(&kind)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", apperrors.ErrMembershipNotFound
		}
		return "", apperrors.ErrDatabase
	}
	return kind, nil
}

func (r *Repository) GetRoleKindByID(ctx context.Context, orgID, roleID uuid.UUID) (string, error) {
	const q = `SELECT kind FROM roles WHERE id = $1 AND organization_id = $2`
	var kind string
	err := r.db.QueryRow(ctx, q, roleID, orgID).Scan(&kind)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", apperrors.ErrMembershipNotFound
		}
		return "", apperrors.ErrDatabase
	}
	return kind, nil
}

// CountActiveOwners locks the counted rows (FOR UPDATE) so two concurrent
// remove/demote requests against the same org can't both read "2 owners"
// and both proceed, this is the row lock the earlier design conversation
// flagged as necessary, not optional, for the invariant to actually hold
// under concurrency. Must be called inside a transaction (the lock is
// released at commit/rollback).
func (r *Repository) CountActiveOwners(ctx context.Context, orgID uuid.UUID) (int, error) {
	const q = `
		SELECT COUNT(*)
		FROM (
			SELECT m.id
			FROM memberships m
			JOIN roles rl ON rl.id = m.role_id
			WHERE m.organization_id = $1 AND rl.kind = 'owner' AND m.status = 'active'
			FOR UPDATE OF m
		) locked_owners
	`
	var count int
	if err := r.db.QueryRow(ctx, q, orgID).Scan(&count); err != nil {
		return 0, apperrors.ErrDatabase
	}
	return count, nil
}

// RemoveMember hard-deletes the membership row. The audit_logs entry
// written alongside this (see Service.Remove) is the historical record,
// there's no need for the membership row itself to persist in a
// "removed" state, and membership_status has no such state to put it in.
func (r *Repository) RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error {
	const q = `DELETE FROM memberships WHERE organization_id = $1 AND user_id = $2`
	tag, err := r.db.Exec(ctx, q, orgID, userID)
	if err != nil {
		return apperrors.ErrDatabase
	}
	if tag.RowsAffected() == 0 {
		return apperrors.ErrMembershipNotFound
	}
	return nil
}

func (r *Repository) UpdateMemberRole(ctx context.Context, orgID, userID, roleID uuid.UUID) error {
	const q = `UPDATE memberships SET role_id = $1 WHERE organization_id = $2 AND user_id = $3`
	tag, err := r.db.Exec(ctx, q, roleID, orgID, userID)
	if err != nil {
		return apperrors.ErrDatabase
	}
	if tag.RowsAffected() == 0 {
		return apperrors.ErrMembershipNotFound
	}
	return nil
}

func (r *Repository) CreateMembership(ctx context.Context, orgID, userID, roleID uuid.UUID) error {
	const q = `
		INSERT INTO memberships (user_id, organization_id, role_id, status)
		VALUES ($1, $2, $3, 'active')
	`
	if _, err := r.db.Exec(ctx, q, userID, orgID, roleID); err != nil {
		return apperrors.ErrDatabase
	}
	return nil
}

// CreateLinkInvitation stores the invitation's token *hash*, reusing
// auth.HashOpaqueToken so every token in this system. Session, refresh,
// invite, is hashed with the same algorithm before it ever touches the
// database, and a leaked DB never hands out a usable invite link.
func (r *Repository) CreateLinkInvitation(ctx context.Context, orgID, roleID, createdBy uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	const q = `
		INSERT INTO invitations (organization_id, invite_type, token, role_id, created_by, expires_at)
		VALUES ($1, 'link', $2, $3, $4, $5)
		RETURNING id
	`
	var id uuid.UUID
	err := r.db.QueryRow(ctx, q, orgID, tokenHash, roleID, createdBy, expiresAt).Scan(&id)
	if err != nil {
		return uuid.Nil, apperrors.ErrDatabase
	}
	return id, nil
}

func (r *Repository) GetActiveInvitationByTokenHash(ctx context.Context, tokenHash string) (*Invitation, error) {
	const q = `
		SELECT id, organization_id, role_id, status, expires_at
		FROM invitations
		WHERE token = $1 AND status = 'active'
	`
	var inv Invitation
	err := r.db.QueryRow(ctx, q, tokenHash).Scan(&inv.ID, &inv.OrganizationID, &inv.RoleID, &inv.Status, &inv.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrInvalidToken
		}
		return nil, apperrors.ErrDatabase
	}
	return &inv, nil
}

// GetInvitationByID scopes by (id, organization_id). Same IDOR pattern
// as every other org-scoped lookup in this codebase: an invitation ID
// from a different org returns "not found," not the invitation.
func (r *Repository) GetInvitationByID(ctx context.Context, orgID, invitationID uuid.UUID) (*Invitation, error) {
	const q = `
		SELECT id, organization_id, role_id, status, expires_at
		FROM invitations
		WHERE id = $1 AND organization_id = $2
	`
	var inv Invitation
	err := r.db.QueryRow(ctx, q, invitationID, orgID).Scan(&inv.ID, &inv.OrganizationID, &inv.RoleID, &inv.Status, &inv.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrOrganizationNotFound
		}
		return nil, apperrors.ErrDatabase
	}
	return &inv, nil
}

// RevokeInvitation is the "nullify" half of "rotate and nullify the
// initial link", matches the same revoke and reissue shape used
// throughout: sessions on refresh, invitations here.
func (r *Repository) RevokeInvitation(ctx context.Context, invitationID uuid.UUID) error {
	const q = `UPDATE invitations SET status = 'revoked' WHERE id = $1 AND status = 'active'`
	tag, err := r.db.Exec(ctx, q, invitationID)
	if err != nil {
		return apperrors.ErrDatabase
	}
	if tag.RowsAffected() == 0 {
		return apperrors.ErrInvalidToken
	}
	return nil
}

func (r *Repository) MarkInvitationAccepted(ctx context.Context, invitationID uuid.UUID) error {
	const q = `UPDATE invitations SET status = 'accepted' WHERE id = $1 AND status = 'active'`
	tag, err := r.db.Exec(ctx, q, invitationID)
	if err != nil {
		return apperrors.ErrDatabase
	}
	if tag.RowsAffected() == 0 {
		// Already accepted/revoked/expired by the time this ran.
		// Treated as an invalid token, same as one that never existed.
		return apperrors.ErrInvalidToken
	}
	return nil
}
