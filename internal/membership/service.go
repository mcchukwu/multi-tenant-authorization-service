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

// Invite blocks personal orgs and lets only an owner hand out the owner
// role.
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

// Accept marks the invitation and inserts the membership in one
// transaction, so a token cannot be redeemed twice.
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

// Remove enforces the owner rules the permission check cannot express:
// only an owner may remove an owner, and the last owner cannot be removed.
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

// AssignRole restricts owner status to owner actors in both directions:
// granting it and revoking it. The last-owner rule applies to demotion.
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

// RotateInvite reissues a link under the same owner restriction as Invite.
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

// Leave is self-service removal. Any member can leave; the last owner
// cannot. Ownership transfer is AssignRole followed by Leave.
func (s *Service) Leave(ctx context.Context, orgID, userID uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)

		// Membership first: a non-member gets the same 404 either way.
		kind, err := txRepo.GetMemberRoleKind(ctx, orgID, userID)
		if err != nil {
			return err
		}

		// No permission gate on this route, so check the org here.
		status, err := txRepo.OrganizationStatus(ctx, orgID)
		if err != nil {
			return err
		}
		if status != "active" {
			return apperrors.ErrOrganizationNotFound
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

func newInviteToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate invite token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
