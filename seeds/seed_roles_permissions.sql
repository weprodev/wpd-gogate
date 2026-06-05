-- ============================================================================
-- SQL Seeder: Roles & Permissions Configuration (PostgreSQL)
-- ============================================================================
-- This script safely seeds standard application roles, permissions, and mappings
-- without requiring pre-determined UUIDs. Run this against your database.

-- ----------------------------------------------------------------------------
-- 1. Seed Roles (If Not Exist)
-- ----------------------------------------------------------------------------
INSERT INTO roles (name, guard_name)
VALUES
    ('admin', 'web'),
    ('editor', 'web'),
    ('writer', 'web'),
    ('viewer', 'web')
ON CONFLICT (name, guard_name) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. Seed Permissions (If Not Exist)
-- ----------------------------------------------------------------------------
INSERT INTO permissions (name, guard_name)
VALUES
    -- User & Member Management
    ('users.list', 'web'),
    ('users.invite', 'web'),
    ('users.remove', 'web'),

    -- Content & Article Actions
    ('articles.create', 'web'),
    ('articles.edit', 'web'),
    ('articles.publish', 'web'),
    ('articles.delete', 'web'),

    -- Administrative & System Settings
    ('settings.read', 'web'),
    ('settings.write', 'web')
ON CONFLICT (name, guard_name) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. Map Permissions to Roles (If Not Already Associated)
-- ----------------------------------------------------------------------------
-- Using subqueries to look up IDs dynamically based on names.

-- --- Admin Role Permissions (Full Access) ---
INSERT INTO role_has_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin' AND p.name IN (
    'users.list', 'users.invite', 'users.remove',
    'articles.create', 'articles.edit', 'articles.publish', 'articles.delete',
    'settings.read', 'settings.write'
)
ON CONFLICT (permission_id, role_id) DO NOTHING;

-- --- Editor Role Permissions ---
INSERT INTO role_has_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'editor' AND p.name IN (
    'users.list',
    'articles.create', 'articles.edit', 'articles.publish', 'articles.delete',
    'settings.read'
)
ON CONFLICT (permission_id, role_id) DO NOTHING;

-- --- Writer Role Permissions ---
INSERT INTO role_has_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'writer' AND p.name IN (
    'articles.create', 'articles.edit'
)
ON CONFLICT (permission_id, role_id) DO NOTHING;

-- --- Viewer Role Permissions ---
INSERT INTO role_has_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'viewer' AND p.name IN (
    'settings.read'
)
ON CONFLICT (permission_id, role_id) DO NOTHING;
