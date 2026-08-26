-- Seed: Template roles (organization_id IS NULL). 
-- These are blueprints, never assigned to a real membership directly 
-- (enforced by the composite FK on memberships.role_id/invitations.role_id, see initial migration).
-- New organizations get their OWN COPY of each of these on creation.
-- Editing a template here only affects future organizations, never existing ones.
--
-- `kind` set explicitly per role — this is the stable identifier invariant logic (min-one-owner, owner-promotes-owner, etc.) 
-- keys off, never `name`, since org admins can rename roles.
--
-- ON CONFLICT targets the partial unique index on template rows specifically (idx_roles_template_name), 
-- not the general UNIQUE(organization_id, name) constraint, 
-- that constraint never fires here since Postgres treats every NULL organization_id as distinct, 
-- so the general constraint alone wouldn't catch a re-run.
INSERT INTO roles (organization_id, name, kind, is_system)
VALUES
(null, 'owner',  'owner',  true),
(null, 'admin',  'admin',  true),
(null, 'member', 'member', true),
(null, 'viewer', 'viewer', true)

ON CONFLICT (name) WHERE organization_id IS NULL DO NOTHING;

--

-- Seed: Template role, Permission Grants Written declaratively (role name, permission key) 
-- and resolved via a join, so this file stays readable, no hardcoded UUIDs.
WITH role_grants (role_name, permission_key) AS (
  VALUES
    -- Owner: everything. Owner is the only role that can delete the org or edit the RBAC config itself.
    ('owner', 'org.view'),
    ('owner', 'org.update'),
    ('owner', 'org.delete'),
    ('owner', 'member.invite'),
    ('owner', 'member.view'),
    ('owner', 'member.assign_role'),
    ('owner', 'member.remove'),
    ('owner', 'role.create'),
    ('owner', 'role.view'),
    ('owner', 'role.update'),
    ('owner', 'role.delete'),
    ('owner', 'resource.create'),
    ('owner', 'resource.view'),
    ('owner', 'resource.update'),
    ('owner', 'resource.delete'),
    ('owner', 'audit_log.view'),

    -- Admin: full operational control, but CANNOT delete the org or edit the RBAC config itself
    ('admin', 'org.view'),
    ('admin', 'org.update'),
    ('admin', 'member.invite'),
    ('admin', 'member.view'),
    ('admin', 'member.remove'),
    ('admin', 'member.assign_role'),
    ('admin', 'role.view'),
    ('admin', 'resource.create'),
    ('admin', 'resource.view'),
    ('admin', 'resource.update'),
    ('admin', 'resource.delete'),
    ('admin', 'audit_log.view'),

    -- Member: day-to-day work, no member/role management
    ('member', 'org.view'),
    ('member', 'member.view'),
    ('member', 'resource.create'),
    ('member', 'resource.view'),
    ('member', 'resource.update'),

    -- Viewer: read-only, lowest trust
    ('viewer', 'org.view'),
    ('viewer', 'resource.view')
)

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM role_grants g
JOIN roles r       ON r.name = g.role_name AND r.organization_id IS NULL
JOIN permissions p ON p.key  = g.permission_key
ON CONFLICT (role_id, permission_id) DO NOTHING;
