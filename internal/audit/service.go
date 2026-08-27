package audit

import (
	"context"
	"encoding/json"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{
		repo: repo,
	}
}

func (s *Service) Log(ctx context.Context, logEntry *LogEntry) error {
	if logEntry.Action == "" {
		return apperrors.ErrInvalidRequestBody
	}

	if logEntry.Metadata == nil {
		logEntry.Metadata = map[string]any{}
	}

	metadata, err := json.Marshal(logEntry.Metadata)
	if err != nil {
		return apperrors.ErrInternalServer
	}

	err = s.repo.Log(ctx, *logEntry, metadata)
	if err != nil {
		return err
	}

	return nil
}
