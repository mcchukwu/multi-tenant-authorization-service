package organization

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
)

type Service struct {
	repo *Repository
	pool *pgxpool.Pool
}

func NewService(repo *Repository, pool *pgxpool.Pool) *Service {
	return &Service{repo: repo, pool: pool}
}

func (s *Service) Get(ctx context.Context, orgID uuid.UUID) (*Organization, error) {
	return s.repo.GetByID(ctx, orgID)
}

// Create always creates a "business" org — orgType is never a parameter
// here and never comes from the request. "personal" is reachable through
// exactly one path: the registration flow, once, per user. This function
// signature is what actually enforces that, not a validation check that
// could be bypassed — there's simply no argument through which a caller
// could ask for "personal".
func (s *Service) Create(ctx context.Context, ownerUserID uuid.UUID, name string) (*Organization, error) {
	var orgID uuid.UUID
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		txRepo := NewRepository(tx)
		var err error
		orgID, err = txRepo.Bootstrap(ctx, name, "business", ownerUserID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, orgID)
}

func (s *Service) UpdateName(ctx context.Context, orgID uuid.UUID, name string) (*Organization, error) {
	return s.repo.UpdateName(ctx, orgID, name)
}

// Delete refuses to delete a personal organization. It's created
// automatically at registration and tied to a user's identity in this
// system — there's always supposed to be exactly one per user, so
// deleting it isn't a supported operation regardless of who's asking or
// what permission they hold.
func (s *Service) Delete(ctx context.Context, orgID uuid.UUID) error {
	org, err := s.repo.GetByID(ctx, orgID)
	if err != nil {
		return err
	}
	if org.Type == "personal" {
		return apperrors.ErrCannotDeletePersonalOrg
	}
	return s.repo.SoftDelete(ctx, orgID)
}
