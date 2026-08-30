package authz

import (
	"context"

	"github.com/google/uuid"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{
		repo: repo,
	}
}

func (s *Service) ListForOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]DecisionView, error) {
	return s.repo.ListForOrg(ctx, orgID, limit, offset)
}
