package audit

import "github.com/google/uuid"

type LogEntry struct {
	OrganizationID *uuid.UUID
	UserID         *uuid.UUID
	Action         string
	EntityType     string
	EntityID       *uuid.UUID
	Metadata       map[string]any
	IPAddress      string
	UserAgent      string
}

/* CREATE TABLE audit_logs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
  user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
  action          TEXT NOT NULL,
  -- e.g. "user.created", "membership.role_changed"

  entity_type     TEXT,
  entity_id       UUID,
  metadata        JSONB,
  ip_address      TEXT,
  user_agent      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
); */
