DELETE FROM permissions WHERE KEY IN (
  'org.view',
  'org.update',
  'org.delete',

  'member.invite',
  'member.view',
  'member.assign_role',
  'member.remove',

  'role.create',
  'role.view',
  'role.update',
  'role.delete',

  'audit_log.view'
);
