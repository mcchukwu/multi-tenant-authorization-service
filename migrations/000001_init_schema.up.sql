-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

--

-- Shared Functions
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

--

-- Users (Global Identities)
CREATE TYPE user_status AS ENUM ('active', 'suspended', 'deleted');

CREATE TABLE users (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email          TEXT UNIQUE,
  phone          TEXT UNIQUE,
  password_hash  TEXT NOT NULL,
  first_name     TEXT NOT NULL,
  last_name      TEXT,
  status         user_status NOT NULL DEFAULT 'active',
  email_verified BOOLEAN NOT NULL DEFAULT false,
  phone_verified BOOLEAN NOT NULL DEFAULT false,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CHECK (email IS NOT NULL OR phone IS NOT NULL)
);

CREATE TRIGGER users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone);

--

-- Organizations (Tenants)
CREATE TYPE organization_status AS ENUM ('active', 'suspended', 'deleted');
CREATE TYPE organization_type AS ENUM ('personal', 'business');

CREATE TABLE organizations (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name       TEXT NOT NULL,
  type       organization_type NOT NULL DEFAULT 'business',
  slug       TEXT UNIQUE,
  status     organization_status NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER organizations_updated_at
BEFORE UPDATE ON organizations
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

--

-- Permissions (the atomic, checkable actions in the system)
CREATE TABLE permissions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key         TEXT UNIQUE NOT NULL,
  -- e.g. 'org.delete', 'invoice.approve', 'member.invite'

  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

--

-- Roles (data-driven, scoped per organization)
CREATE TYPE role_kind AS ENUM ('owner', 'admin', 'member', 'viewer', 'custom');

CREATE TABLE roles (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  -- NULL organization_id = system-wide template role (seeded defaults, cloned into each org at creation time, 
  -- never assigned directly, see composite FK below)

  name            TEXT NOT NULL,
  kind            role_kind NOT NULL DEFAULT 'custom',
  -- stable identifier for invariant logic (owner checks etc.), never key off `name`, since org admins can rename roles

  is_system       BOOLEAN NOT NULL DEFAULT FALSE,
  -- TRUE = seeded default (owner/admin/member/viewer), protected from deletion

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- composite unique target for the cross-tenant FK below
  UNIQUE(organization_id, id),

  -- partial unique: name must be unique within a real org; template rows (organization_id IS NULL) are excluded 
  -- since NULL <> NULL would otherwise let duplicate template names slip through unnoticed
  CONSTRAINT roles_org_name_unique UNIQUE (organization_id, name)
);

CREATE TRIGGER roles_updated_at
BEFORE UPDATE ON roles
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_roles_organization_id ON roles(organization_id);
CREATE UNIQUE INDEX idx_roles_template_name ON roles(name) WHERE organization_id IS NULL;

--

-- Role Permissions (which permissions a role grants)
CREATE TABLE role_permissions (
  role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

--

-- Memberships (multi-tenancy bridge, also points at a role)
CREATE TYPE membership_status AS ENUM ('active', 'invited', 'suspended');

CREATE TABLE memberships (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
  -- RESTRICT: can't delete a role while members still hold it

  status          membership_status NOT NULL DEFAULT 'active',
  joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE(user_id, organization_id),

  -- cross-tenant integrity: role must belong to the SAME org as the membership. 
  -- Also means memberships can never reference a NULL org template role directly, 
  -- since NULL never satisfies FK equality, orgs must be assigned their own cloned copy of a role.
  CONSTRAINT memberships_role_org_fk
    FOREIGN KEY (organization_id, role_id) REFERENCES roles(organization_id, id)
);

CREATE TRIGGER memberships_updated_at
BEFORE UPDATE ON memberships
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_memberships_organization_id ON memberships(organization_id);
CREATE INDEX idx_memberships_role_id ON memberships(role_id);

--

-- Invitations (organization level)
-- this service manages access to isolated tenant orgs generically
CREATE TYPE invite_type AS ENUM ('link', 'email');
CREATE TYPE invite_status AS ENUM ('active', 'revoked', 'accepted', 'expired');

CREATE TABLE invitations (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  invite_type     invite_type NOT NULL,
  token           TEXT,
  email           TEXT,
  role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
  status          invite_status NOT NULL DEFAULT 'active',
  created_by      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL,

  CHECK (
    (invite_type = 'link'  AND token IS NOT NULL AND email IS NULL) OR
    (invite_type = 'email' AND email IS NOT NULL AND token IS NULL)
  ),

  -- same cross-tenant guard as memberships: an invite can only grant a role that belongs to the org it's inviting into
  CONSTRAINT invitations_role_org_fk
    FOREIGN KEY (organization_id, role_id) REFERENCES roles(organization_id, id)
);

CREATE TRIGGER invitations_updated_at
BEFORE UPDATE ON invitations
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- only one ACTIVE token per lineage, "rotate the link" = revoke old row, insert new one, both preserved for audit history
CREATE UNIQUE INDEX idx_active_invite_token ON invitations(token) WHERE status = 'active';
CREATE INDEX idx_invitations_organization_id ON invitations(organization_id);

--

-- Sessions (auth + device tracking, with refresh token rotation support)
CREATE TABLE sessions (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_family_id          UUID NOT NULL DEFAULT gen_random_uuid(),
  -- shared across all rotated tokens in one continuous session lineage; reuse of a revoked token => revoke entire family (theft signal)

  refresh_token_hash       TEXT UNIQUE NOT NULL,
  access_token_hash        TEXT UNIQUE NOT NULL,
  user_agent               TEXT,
  ip_address               TEXT,
  revoked                  BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at               TIMESTAMPTZ,
  access_token_expires_at  TIMESTAMPTZ NOT NULL,
  refresh_token_expires_at TIMESTAMPTZ NOT NULL,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- NOTE: created_at is not updated when a token is rotated, so it's not a reliable indicator of session lifetime

  CHECK (
    (revoked = FALSE AND revoked_at IS NULL) OR
    (revoked = TRUE  AND revoked_at IS NOT NULL)
  )
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_family_id ON sessions(token_family_id);
CREATE INDEX idx_sessions_cleanup ON sessions(refresh_token_expires_at) WHERE revoked = FALSE;

--

-- Audit Logs (business events, what successfully happened)
CREATE TABLE audit_logs (
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
);

CREATE INDEX idx_audit_logs_org_created ON audit_logs(organization_id, created_at);

--

-- Authz Decisions (every authorization check, allowed or denied)
CREATE TABLE authz_decisions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
  user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
  permission_key  TEXT NOT NULL,
  -- denormalized snapshot, not a FK, so the log still reads correctly even if the permission is later renamed or deleted

  resource_type   TEXT,
  resource_id     UUID,
  allowed         BOOLEAN NOT NULL,
  reason          TEXT,
  -- e.g. "role lacks permission", "resource outside tenant scope"

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_authz_decisions_org_created ON authz_decisions(organization_id, created_at);
CREATE INDEX idx_authz_decisions_user_id ON authz_decisions(user_id);
