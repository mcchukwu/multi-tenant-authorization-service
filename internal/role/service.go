package role

import (
	"context"

	"github.com/google/uuid"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]Role, error) {
	return s.repo.ListByOrg(ctx, orgID)
}
