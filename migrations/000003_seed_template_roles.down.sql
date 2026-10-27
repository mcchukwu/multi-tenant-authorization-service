DELETE FROM role_permissions
WHERE role_id IN (SELECT id FROM roles WHERE organization_id IS NULL);

DELETE FROM roles WHERE organization_id IS NULL;
