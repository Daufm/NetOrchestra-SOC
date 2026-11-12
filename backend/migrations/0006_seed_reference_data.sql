-- Phase 2 / 0006: reference data. No users or secrets are seeded; the first admin
-- is created by the secure bootstrap flow in Phase 3.

INSERT INTO roles (id, name, description) VALUES
    (1, 'ADMIN',   'Full administrative and platform access'),
    (2, 'ANALYST', 'Investigations, authorized captures, uploads, findings and evidence'),
    (3, 'VIEWER',  'Read-only dashboard, findings and investigations');

INSERT INTO permissions (code, description) VALUES
    ('users:manage',          'Create, disable and reset users'),
    ('sessions:manage_all',   'View and revoke any user''s sessions'),
    ('audit:read',            'Read audit logs'),
    ('profiles:manage',       'Edit detection profiles and thresholds'),
    ('investigations:write',  'Create and modify investigations'),
    ('investigations:read',   'View investigations'),
    ('jobs:create',           'Start uploads and remote captures'),
    ('jobs:stop',             'Stop running capture jobs'),
    ('jobs:read',             'View jobs and packets'),
    ('findings:read',         'View threat findings'),
    ('findings:triage',       'Change finding status'),
    ('evidence:read',         'View evidence metadata'),
    ('evidence:export',       'Export verified evidence');

INSERT INTO role_permissions (role_id, permission_id)
    SELECT 1, id FROM permissions;                                   -- ADMIN: everything

INSERT INTO role_permissions (role_id, permission_id)
    SELECT 2, id FROM permissions WHERE code IN (
        'investigations:write', 'investigations:read', 'jobs:create', 'jobs:stop', 'jobs:read',
        'findings:read', 'findings:triage', 'evidence:read', 'evidence:export');

INSERT INTO role_permissions (role_id, permission_id)
    SELECT 3, id FROM permissions WHERE code IN (
        'investigations:read', 'jobs:read', 'findings:read');

INSERT INTO detection_profiles (id, label, description, thresholds) VALUES
    ('dns_tunnel',
     '🌐 Hunt DNS Tunneling (>50 Chars)',
     'Long or high-entropy DNS labels, high query rates, suspicious TXT activity',
     '{"max_label_len": 50, "min_entropy": 3.5, "queries_per_minute": 120, "txt_ratio": 0.3}'::jsonb),
    ('cleartext_http',
     '🔑 Hunt Cleartext HTTP Logins',
     'Basic auth, login-style POSTs and sensitive parameters/headers in unencrypted HTTP; credentials are redacted',
     '{"sensitive_params": ["password", "passwd", "pwd", "token", "apikey"], "flag_basic_auth": true}'::jsonb),
    ('remote_access',
     '🛑 Hunt Suspicious Remote Traffic (RDP/SSH)',
     'Unusual RDP/SSH ports, connection frequency, sources and timing',
     '{"ports": [22, 3389], "connections_per_minute": 30, "distinct_sources": 10}'::jsonb);
