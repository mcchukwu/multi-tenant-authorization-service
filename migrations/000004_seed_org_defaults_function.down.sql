DROP TRIGGER IF EXISTS organizations_provision_roles ON organizations;

DELETE FROM role_permissions
WHERE role_id IN (
    SELECT id 
    FROM roles 
    WHERE organization_id IS NOT NULL
);

DELETE FROM roles 
WHERE organization_id IS NOT NULL;

DROP FUNCTION IF EXISTS trigger_provision_default_roles();
DROP FUNCTION IF EXISTS provision_default_roles(UUID);
