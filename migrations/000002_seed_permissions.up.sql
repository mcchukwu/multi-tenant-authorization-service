-- Seed: Permissions (global catalog — not org-scoped)
-- These are the atomic actions the middleware will check against, e.g. `CanUser(userID, orgID, "project.delete", resourceID)`.
INSERT INTO permissions(
  key,
  description
)
VALUES 
(
  'org.view',
  'View organization details'
),
(
  'org.update',
  'Edit organization name, slug, settings'
),
(
  'org.delete',
  'Delete the organization'
),

(
  'member.invite',
  'Invite a new member to the organization'
),
(
  'member.view',
  'View organization members'
),
(
  'member.assign_role',
  'Change another member's role'
),
(
  'member.remove',
  'Remove a member from the organization'
),

(
  'role.create',
  'Create a custom role'
),
(
  'role.view',
  'View roles and permissions'
),
(
  'role.update',
  'Edit a role's permission grants'
),
(
  'role.delete',
  'Delete a custom role'
),

-- example domain resource: "project" (swap for real resource)
(
  'project.create',
  'Create a project'
),
(
  'project.view',
  'View a project'
),
(
  'project.update',
  'Edit a project'
),
(
  'project.delete',
  'Delete a project'
),

-- audit / observability
(
  'audit_log.view',
  'View the organization's audit log'
)

ON CONFLICT (KEY) DO NOTHING;
