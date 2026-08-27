package audit

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
)

type Repo struct {
	db *pgxpool.Pool
}

func NewRepo(db *pgxpool.Pool) *Repo {
	return &Repo{
		db: db,
	}
}

func (r *Repo) Log(ctx context.Context, logEntry LogEntry, metadata []byte) error {
	ctx, cancel := db.WithDBTimeout(ctx)
	defer cancel()

	_, err := r.db.Exec(ctx, `
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
