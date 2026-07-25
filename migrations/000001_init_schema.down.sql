-- Authz Decisions
DROP INDEX IF EXISTS idx_authz_decisions_user_id;
DROP INDEX IF EXISTS idx_authz_decisions_org_created;
DROP TABLE IF EXISTS authz_decisions;
-- Audit Logs
DROP INDEX IF EXISTS idx_audit_logs_org_created;
DROP TABLE IF EXISTS audit_logs;
-- Sessions
DROP INDEX IF EXISTS idx_sessions_token_family_id;
DROP INDEX IF EXISTS idx_sessions_user_id;
DROP TABLE IF EXISTS sessions;
-- Memberships
DROP INDEX IF EXISTS idx_memberships_role_id;
DROP INDEX IF EXISTS idx_unique_membership;
DROP TRIGGER IF EXISTS memberships_updated_at
ON memberships;
DROP TABLE IF EXISTS memberships;
DROP TYPE IF EXISTS membership_status;
-- Role Permissions
DROP INDEX IF EXISTS idx_role_permissions_permission_id;
DROP TABLE IF EXISTS role_permissions;
-- Roles
DROP INDEX IF EXISTS idx_roles_organization_id;
DROP TRIGGER IF EXISTS roles_updated_at
ON roles;
DROP TABLE IF EXISTS roles;
-- Permissions
DROP TABLE IF EXISTS permissions;
-- Organizations
DROP TRIGGER IF EXISTS organizations_updated_at
ON organizations;
DROP TABLE IF EXISTS organizations;
DROP TYPE IF EXISTS organization_status;
-- Users
DROP INDEX IF EXISTS idx_users_phone;
DROP INDEX IF EXISTS idx_users_email;
DROP TRIGGER IF EXISTS users_updated_at
ON users;
DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS user_status;
-- Shared Functions
DROP FUNCTION IF EXISTS update_updated_at_column();
