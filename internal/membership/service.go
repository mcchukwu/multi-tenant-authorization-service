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

// Invite creates a rotatable link invitation. Blocks personal orgs
// unconditionally, before any invitation row is created
//
// Only an owner can invite someone in as another owner, the generic
// member.invite permission proves the caller can invite people at all,
// not that they're trusted to mint new owners specifically.
func (s *Service) Invite(ctx context.Context, orgID, inviterID, roleID uuid.UUID) (*InviteResult, error) {
	orgType, err := s.repo.GetOrganizationType(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if orgType == "personal" {
		return nil, apperrors.ErrPersonalWorkspace
	}

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
// concurrent requests racing on the same link the second request's
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
// only an owner may remove another owner, an admin holds member.remove
// generally, but never against an owner target, regardless of how many
// owners currently exist and separately, the min one owner invariant:
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
// permission, both owner-only regardless of direction: granting the
// owner role to someone new, and taking owner status away from someone
// who currently has it, are equally sensitive an admin can reassign
// roles generally, but never touch anyone's owner status either way.
// The min one owner invariant is checked separately, inside the same
// transaction, for the demotion case specifically.
func (s *Service) AssignRole(ctx context.Context, orgID, actorID, targetUserID, newRoleID uuid.UUID) error {
	newKind, err := s.repo.GetRoleKindByID(ctx, orgID, newRoleID)
	if err != nil {
		return err
	}

	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)

		currentKind, err := txRepo.GetMemberRoleKind(ctx, orgID, targetUserID)
		if err != nil {
			return err
		}

		if newKind == "owner" || currentKind == "owner" {
			actorKind, err := txRepo.GetMemberRoleKind(ctx, orgID, actorID)
			if err != nil {
				return err
			}
			if actorKind != "owner" {
				return apperrors.ErrOwnerActionRestricted
			}
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

// RotateInvite revokes an org's existing active invitation and issues a
// new token on the same role grant, same revoke and reissue pattern
// refresh token rotation uses, and the same owner-target restriction as
// creating a fresh invite (an admin still can't mint access to the owner
// role, whether by inviting fresh or rotating an existing invite).
func (s *Service) RotateInvite(ctx context.Context, orgID, actorID, invitationID uuid.UUID) (*InviteResult, error) {
	inv, err := s.repo.GetInvitationByID(ctx, orgID, invitationID)
	if err != nil {
		return nil, err
	}

	targetKind, err := s.repo.GetRoleKindByID(ctx, orgID, inv.RoleID)
	if err != nil {
		return nil, err
	}
	if targetKind == "owner" {
		actorKind, err := s.repo.GetMemberRoleKind(ctx, orgID, actorID)
		if err != nil {
			return nil, err
		}
		if actorKind != "owner" {
			return nil, apperrors.ErrOwnerActionRestricted
		}
	}

	rawToken, err := newInviteToken()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(invitationTTL)

	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)
		if err := txRepo.RevokeInvitation(ctx, inv.ID); err != nil {
			return err
		}
		_, err := txRepo.CreateLinkInvitation(ctx, orgID, inv.RoleID, actorID, auth.HashOpaqueToken(rawToken), expiresAt)
		return err
	})
	if err != nil {
		return nil, err
	}

	return &InviteResult{Token: rawToken, ExpiresAt: expiresAt}, nil
}

// Leave is the self-service version of Remove, a member removing
// themselves. Reuses the exact same min one owner invariant: the org's
// last owner can't leave, full stop. To leave, the last owner has to
// first grant someone else the owner role via AssignRole, at that
// point there are two owners, and leaving no longer violates the
// invariant. That composition (AssignRole + Leave) is also the entire
// ownership transfer mechanism this system needs; no separate
// "transfer ownership" endpoint required.
//
// Unlike Remove, there's no actor-kind restriction here, the
// only an owner removes an owner rule exists to stop someone *else*
// from removing an owner against their will, not to stop an owner from
// removing themselves voluntarily. Any member, any role, can leave.
func (s *Service) Leave(ctx context.Context, orgID, userID uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)

		kind, err := txRepo.GetMemberRoleKind(ctx, orgID, userID)
		if err != nil {
			return err
		}

		if kind == "owner" {
			count, err := txRepo.CountActiveOwners(ctx, orgID)
			if err != nil {
				return err
			}
			if count <= 1 {
				return apperrors.ErrLastOwner
			}
		}

		return txRepo.RemoveMember(ctx, orgID, userID)
	})
}

// newInviteToken is deliberately separate from auth's token generation.
// It needs the same random-generation shape but none of the opaque
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
