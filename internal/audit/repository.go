package audit

import (
	"context"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
)

type Repository struct {
	dbQuerier db.Querier
}

func NewRepository(db db.Querier) *Repository {
	return &Repository{
		dbQuerier: db,
	}
}

func (r *Repository) Log(ctx context.Context, logEntry LogEntry, metadata []byte) error {
	ctx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	_, err := r.dbQuerier.Exec(ctx, `
		INSERT INTO audit_logs (
			organization_id, 
			user_id, 
			action, 
			entity_type, 
			entity_id, 
			metadata,
		  ip_address,
		  user_agent
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, logEntry.OrganizationID, logEntry.UserID, logEntry.Action, logEntry.EntityType, logEntry.EntityID, metadata, logEntry.IPAddress, logEntry.UserAgent)
	if err != nil {
		return apperrors.ErrDatabase
	}

	return nil
}
