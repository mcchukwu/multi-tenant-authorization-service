package membership

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/auth"
)

const invitationTTL = 7 * 24 * time.Hour

type Service struct {
	repo *Repository
	pool *pgxpool.Pool
}

func NewService(repo *Repository, pool *pgxpool.Pool) *Service {
	return &Service{repo: repo, pool: pool}
}

func (s *Service) ListMembers(ctx context.Context, orgID uuid.UUID) ([]Member, error) {
	return s.repo.ListMembers(ctx, orgID)
}

type InviteResult struct {
	Token     string
	ExpiresAt time.Time
}

// Invite creates a rotatable link invitation. Only an owner can invite
// someone in as another owner — the generic member.invite permission
// proves the caller can invite people at all, not that they're trusted
// to mint new owners specifically. That distinction has to be enforced
// here, since role_permissions has no concept of "grant this permission,
// but only for non-owner targets."
func (s *Service) Invite(ctx context.Context, orgID, inviterID, roleID uuid.UUID) (*InviteResult, error) {
	targetKind, err := s.repo.GetRoleKindByID(ctx, orgID, roleID)
	if err != nil {
		return nil, err
	}
	if targetKind == "owner" {
		inviterKind, err := s.repo.GetMemberRoleKind(ctx, orgID, inviterID)
		if err != nil {
			return nil, err
		}
		if inviterKind != "owner" {
			return nil, apperrors.ErrOwnerActionRestricted
		}
	}

	rawToken, err := newInviteToken()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(invitationTTL)

	if _, err := s.repo.CreateLinkInvitation(ctx, orgID, roleID, inviterID, auth.HashOpaqueToken(rawToken), expiresAt); err != nil {
		return nil, err
	}

	return &InviteResult{Token: rawToken, ExpiresAt: expiresAt}, nil
}

// Accept turns a valid invitation into a membership. Marking the
// invitation accepted and inserting the membership happen in one
// transaction, so a token can't be redeemed twice even under two
// concurrent requests racing on the same link — the second request's
// MarkInvitationAccepted finds zero rows affected (status is no longer
// 'active') and the whole transaction rolls back.
func (s *Service) Accept(ctx context.Context, userID uuid.UUID, rawToken string) (uuid.UUID, error) {
	inv, err := s.repo.GetActiveInvitationByTokenHash(ctx, auth.HashOpaqueToken(rawToken))
	if err != nil {
		return uuid.Nil, err
	}
	if time.Now().After(inv.ExpiresAt) {
		return uuid.Nil, apperrors.ErrInvalidToken
	}

	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)
		if err := txRepo.MarkInvitationAccepted(ctx, inv.ID); err != nil {
			return err
		}
		return txRepo.CreateMembership(ctx, inv.OrganizationID, userID, inv.RoleID)
	})
	if err != nil {
		return uuid.Nil, err
	}
	return inv.OrganizationID, nil
}

// Remove enforces two things above the generic member.remove permission:
// only an owner may remove another owner — an admin holds member.remove
// generally, but never against an owner target, regardless of how many
// owners currently exist — and separately, the min-one-owner invariant:
// the org's last owner can never be removed by anyone. Both checks run
// inside one transaction against the same locked owner-count read.
func (s *Service) Remove(ctx context.Context, orgID, actorID, targetUserID uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)

		targetKind, err := txRepo.GetMemberRoleKind(ctx, orgID, targetUserID)
		if err != nil {
			return err
		}

		if targetKind == "owner" {
			actorKind, err := txRepo.GetMemberRoleKind(ctx, orgID, actorID)
			if err != nil {
				return err
			}
			if actorKind != "owner" {
				return apperrors.ErrOwnerActionRestricted
			}

			count, err := txRepo.CountActiveOwners(ctx, orgID)
			if err != nil {
				return err
			}
			if count <= 1 {
				return apperrors.ErrLastOwner
			}
		}

		return txRepo.RemoveMember(ctx, orgID, targetUserID)
	})
}

// AssignRole enforces two rules above the generic member.assign_role
// permission: only an owner can grant the owner role to someone else,
// and demoting the org's only owner away from 'owner' is blocked by the
// same min-one-owner invariant Remove enforces — losing your last owner
// via a role change is exactly as dangerous as losing them via removal,
// so it gets the same guard.
func (s *Service) AssignRole(ctx context.Context, orgID, actorID, targetUserID, newRoleID uuid.UUID) error {
	newKind, err := s.repo.GetRoleKindByID(ctx, orgID, newRoleID)
	if err != nil {
		return err
	}

	if newKind == "owner" {
		actorKind, err := s.repo.GetMemberRoleKind(ctx, orgID, actorID)
		if err != nil {
			return err
		}
		if actorKind != "owner" {
			return apperrors.ErrOwnerActionRestricted
		}
	}

	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)

		currentKind, err := txRepo.GetMemberRoleKind(ctx, orgID, targetUserID)
		if err != nil {
			return err
		}
		if currentKind == "owner" && newKind != "owner" {
			count, err := txRepo.CountActiveOwners(ctx, orgID)
			if err != nil {
				return err
			}
			if count <= 1 {
				return apperrors.ErrLastOwner
			}
		}
		return txRepo.UpdateMemberRole(ctx, orgID, targetUserID, newRoleID)
	})
}

// newInviteToken is deliberately separate from auth's token generation —
// it needs the same random-generation shape but none of the opaque
// session-token semantics, and importing auth only for HashOpaqueToken
// (used above, at storage time) keeps that dependency to exactly the one
// thing this package actually needs from it.
func newInviteToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate invite token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
