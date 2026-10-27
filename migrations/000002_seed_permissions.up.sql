-- Seed: Permissions (global catalog, not org-scoped). These are the atomic actions the middleware will check against, 
-- e.g. `CanUser(userID, orgID, "member.invite")`.
INSERT INTO permissions (key, description)
VALUES
-- organization / membership management
('org.view',              'View organization details and settings'),
('org.update',            'Edit organization name, slug, settings'),
('org.delete',            'Delete the organization'),
('member.invite',         'Invite a new member to the organization'),
('member.view',           'View the organization''s member list and roles'),
('member.assign_role',    'Change another member''s role'),
('member.remove',         'Remove a member from the organization'),

-- role/permission administration (meta, who can edit the RBAC config itself)
('role.create',           'Create a custom role'),
('role.view',             'View roles and their permission grants'),
('role.update',           'Edit a role''s permission grants'),
('role.delete',           'Delete a custom role'),

-- audit / observability
('audit_log.view',        'View the organization''s audit log')

ON CONFLICT (key) DO NOTHING;
