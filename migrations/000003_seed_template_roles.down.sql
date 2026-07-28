DELETE FROM roles WHERE name IN (
  'owner', 
  'admin', 
  'member', 
  'viewer'
);

DELETE FROM role_permissions WHERE role_id IN (
  SELECT id FROM roles WHERE name IN (
    'owner', 
    'admin', 
    'member', 
    'viewer'
  )
);
