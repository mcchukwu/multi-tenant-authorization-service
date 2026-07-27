-- Function: provision_default_roles(organization_id)
-- Clones every template role (organization_id IS NULL) into
-- org-scoped copies, along with each template's permission grants.
-- Called automatically via trigger on organization creation
-- Can also be called manually/idempotently
-- if you ever need to re-seed an org (e.g. after a bug wiped roles).
CREATE OR REPLACE FUNCTION provision_default_roles(p_organization_id UUID)
RETURNS VOID AS $$
BEGIN
  -- Step 1: copy each template role into this org, preserving name + is_system
  INSERT INTO roles (organization_id, name, is_system)
  SELECT p_organization_id, r.name, r.is_system
  FROM roles r
  WHERE r.organization_id IS NULL
  ON CONFLICT (organization_id, name) DO NOTHING;

  -- Step 2: copy each template's permission grants onto the new org-scoped role of the same name
  INSERT INTO role_permissions (role_id, permission_id)
  SELECT org_role.id, rp.permission_id
  FROM roles template_role
  JOIN role_permissions rp   ON rp.role_id = template_role.id
  JOIN roles org_role        ON org_role.organization_id = p_organization_id
                             AND org_role.name = template_role.name
  WHERE template_role.organization_id IS NULL
  ON CONFLICT (role_id, permission_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- Trigger: fire provision_default_roles() after every org insert
CREATE OR REPLACE FUNCTION trigger_provision_default_roles()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM provision_default_roles(NEW.id);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER organizations_provision_roles
AFTER INSERT ON organizations
FOR EACH ROW
EXECUTE FUNCTION trigger_provision_default_roles();
