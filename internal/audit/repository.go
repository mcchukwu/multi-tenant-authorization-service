package audit

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
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

// ListForOrg reads back what Log has been writing since the login
// endpoint was first built. Assumes Repo's db field is typed db.Querier
// (per the earlier repository-consistency pass) — flag if that hasn't
// landed in this package yet, since this method depends on it.
func (r *Repository) ListForOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]LogEntryView, error) {
	const q = `
		SELECT id, user_id, action, entity_type, entity_id, metadata, ip_address, user_agent, created_at
		FROM audit_logs
		WHERE organization_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.dbQuerier.Query(ctx, q, orgID, limit, offset)
	if err != nil {
		return nil, apperrors.ErrDatabase
	}
	defer rows.Close()

	var out []LogEntryView
	for rows.Next() {
		var e LogEntryView
		var rawMetadata []byte
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.EntityType, &e.EntityID, &rawMetadata, &e.IPAddress, &e.UserAgent, &e.CreatedAt); err != nil {
			return nil, apperrors.ErrDatabase
		}
		if len(rawMetadata) > 0 {
			_ = json.Unmarshal(rawMetadata, &e.Metadata)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, apperrors.ErrDatabase
	}
	return out, nil
}
