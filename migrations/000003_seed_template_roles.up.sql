-- Seed: Template roles (organization_id IS NULL)
-- These are blueprints, never assigned to a real membership directly.
-- New organizations get their OWN COPY of each of these on creation
-- Editing a template here only affects future organizations, never existing ones.
INSERT INTO roles (organization_id, name, is_system) VALUES
    (NULL, 'owner',  TRUE),
    (NULL, 'admin',  TRUE),
    (NULL, 'member', TRUE),
    (NULL, 'viewer', TRUE)
ON CONFLICT (organization_id, name) DO NOTHING;

-- Seed: Template role -> Permission Grants
-- Written declaratively (role name -> permission key) and resolved via a join, so this file stays readable — no hardcoded UUIDs.
WITH role_grants (role_name, permission_key) AS (
    VALUES
        -- Owner: everything. Owner is the only role that can touch role/permission config and delete the org itself.
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
        ('owner', 'project.create'),
        ('owner', 'project.view'),
        ('owner', 'project.update'),
        ('owner', 'project.delete'),
        ('owner', 'audit_log.view'),

        -- Admin: full operational control, but CANNOT delete the org or edit the RBAC config itself
        ('admin', 'org.view'),
        ('admin', 'org.update'),
        ('admin', 'member.invite'),
        ('admin', 'member.view'),
        ('admin', 'member.remove'),
        ('admin', 'member.assign_role'),
        ('admin', 'role.view'),
        ('admin', 'project.create'),
        ('admin', 'project.view'),
        ('admin', 'project.update'),
        ('admin', 'project.delete'),
        ('admin', 'audit_log.view'),

        -- Member: day-to-day work, no member/role management
        ('member', 'org.view'),
        ('member', 'member.view'),
        ('member', 'project.create'),
        ('member', 'project.view'),
        ('member', 'project.update'),

        -- VIEWER: read-only, lowest trust
        ('viewer', 'org.view'),
        ('viewer', 'project.view')
)

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM role_grants g
JOIN roles r        ON r.name = g.role_name AND r.organization_id IS NULL
JOIN permissions p  ON p.key  = g.permission_key

ON CONFLICT (role_id, permission_id) DO NOTHING;
