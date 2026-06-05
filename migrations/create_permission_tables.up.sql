-- =====================================================
-- 1. roles
-- =====================================================
CREATE TABLE IF NOT EXISTS roles (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL,
    guard_name   TEXT        NOT NULL DEFAULT 'web',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT roles_name_guard_unique UNIQUE (name, guard_name)
);

-- =====================================================
-- 2. permissions
-- =====================================================
CREATE TABLE IF NOT EXISTS permissions (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL,
    guard_name   TEXT        NOT NULL DEFAULT 'web',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT permissions_name_guard_unique UNIQUE (name, guard_name)
);

-- =====================================================
-- 3. role_has_permissions
-- =====================================================
CREATE TABLE IF NOT EXISTS role_has_permissions (
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (permission_id, role_id)
);

-- =====================================================
-- 4. model_has_roles
-- =====================================================
CREATE TABLE IF NOT EXISTS model_has_roles (
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    model_type TEXT NOT NULL,
    model_id   UUID NOT NULL,
    team_id    UUID, -- Optional team_id/workspace_id foreign key for scoping
    PRIMARY KEY (role_id, model_id, model_type, team_id)
);
CREATE INDEX IF NOT EXISTS idx_model_has_roles_lookup ON model_has_roles (model_id, model_type, team_id);

-- =====================================================
-- 5. model_has_permissions
-- =====================================================
CREATE TABLE IF NOT EXISTS model_has_permissions (
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    model_type    TEXT NOT NULL,
    model_id      UUID NOT NULL,
    team_id       UUID, -- Optional team_id/workspace_id foreign key for scoping
    PRIMARY KEY (permission_id, model_id, model_type, team_id)
);
CREATE INDEX IF NOT EXISTS idx_model_has_permissions_lookup ON model_has_permissions (model_id, model_type, team_id);
