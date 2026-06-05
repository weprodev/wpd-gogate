package gogate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ModelRef provides a fluent, scoped API for a specific model (e.g., User, APIKey)
// in the context of an optional team or workspace.
type ModelRef struct {
	gate      *Gate
	modelType string
	modelID   any
	teamID    any
}

// Model constructs a ModelRef for checking permissions and managing roles/permissions.
func (g *Gate) Model(modelType string, modelID any, teamID any) *ModelRef {
	return &ModelRef{
		gate:      g,
		modelType: modelType,
		modelID:   modelID,
		teamID:    teamID,
	}
}

// Can checks if the model has the specified permission.
func (m *ModelRef) Can(ctx context.Context, permissionName string) (bool, error) {
	return m.gate.Check(ctx, m.modelType, m.modelID, permissionName, m.teamID)
}

// AssignRole assigns the given role to the model.
func (m *ModelRef) AssignRole(ctx context.Context, roleName string) error {
	// First get the role ID
	queryRole := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 LIMIT 1", m.gate.cfg.RolesTable)
	var roleID string
	err := m.gate.db.QueryRowContext(ctx, queryRole, roleName).Scan(&roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("wpd-gogate: role %q not found: %w", roleName, err)
		}
		return fmt.Errorf("wpd-gogate: lookup role ID: %w", err)
	}

	// Insert or do nothing on conflict
	queryInsert := fmt.Sprintf(`
		INSERT INTO %s (role_id, model_type, model_id, team_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (role_id, model_id, model_type, team_id) DO NOTHING
	`, m.gate.cfg.ModelHasRolesTable)

	_, err = m.gate.db.ExecContext(ctx, queryInsert, roleID, m.modelType, m.modelID, m.teamID)
	if err != nil {
		return fmt.Errorf("wpd-gogate: assign role to model: %w", err)
	}

	return nil
}

// RemoveRole removes the given role from the model.
func (m *ModelRef) RemoveRole(ctx context.Context, roleName string) error {
	// First get the role ID
	queryRole := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 LIMIT 1", m.gate.cfg.RolesTable)
	var roleID string
	err := m.gate.db.QueryRowContext(ctx, queryRole, roleName).Scan(&roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // Role doesn't exist, so nothing to remove
		}
		return fmt.Errorf("wpd-gogate: lookup role ID: %w", err)
	}

	queryDelete := fmt.Sprintf(`
		DELETE FROM %s
		WHERE role_id = $1 AND model_type = $2 AND model_id = $3 AND team_id IS NOT DISTINCT FROM $4
	`, m.gate.cfg.ModelHasRolesTable)

	_, err = m.gate.db.ExecContext(ctx, queryDelete, roleID, m.modelType, m.modelID, m.teamID)
	if err != nil {
		return fmt.Errorf("wpd-gogate: remove role from model: %w", err)
	}

	return nil
}

// GivePermissionTo assigns a direct permission override to the model.
func (m *ModelRef) GivePermissionTo(ctx context.Context, permissionName string) error {
	// Get the permission ID
	queryPermission := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 LIMIT 1", m.gate.cfg.PermissionsTable)
	var permissionID string
	err := m.gate.db.QueryRowContext(ctx, queryPermission, permissionName).Scan(&permissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("wpd-gogate: permission %q not found: %w", permissionName, err)
		}
		return fmt.Errorf("wpd-gogate: lookup permission ID: %w", err)
	}

	queryInsert := fmt.Sprintf(`
		INSERT INTO %s (permission_id, model_type, model_id, team_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (permission_id, model_id, model_type, team_id) DO NOTHING
	`, m.gate.cfg.ModelHasPermissionsTable)

	_, err = m.gate.db.ExecContext(ctx, queryInsert, permissionID, m.modelType, m.modelID, m.teamID)
	if err != nil {
		return fmt.Errorf("wpd-gogate: give permission to model: %w", err)
	}

	return nil
}

// RevokePermissionTo removes a direct permission override from the model.
func (m *ModelRef) RevokePermissionTo(ctx context.Context, permissionName string) error {
	queryPermission := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 LIMIT 1", m.gate.cfg.PermissionsTable)
	var permissionID string
	err := m.gate.db.QueryRowContext(ctx, queryPermission, permissionName).Scan(&permissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // Permission doesn't exist, so nothing to revoke
		}
		return fmt.Errorf("wpd-gogate: lookup permission ID: %w", err)
	}

	queryDelete := fmt.Sprintf(`
		DELETE FROM %s
		WHERE permission_id = $1 AND model_type = $2 AND model_id = $3 AND team_id IS NOT DISTINCT FROM $4
	`, m.gate.cfg.ModelHasPermissionsTable)

	_, err = m.gate.db.ExecContext(ctx, queryDelete, permissionID, m.modelType, m.modelID, m.teamID)
	if err != nil {
		return fmt.Errorf("wpd-gogate: revoke permission from model: %w", err)
	}

	return nil
}

// GetRoleNames returns the names of all roles assigned to the model.
func (m *ModelRef) GetRoleNames(ctx context.Context) ([]string, error) {
	query := fmt.Sprintf(`
		SELECT r.name FROM %s mhr
		JOIN %s r ON r.id = mhr.role_id
		WHERE mhr.model_type = $1 AND mhr.model_id = $2 AND mhr.team_id IS NOT DISTINCT FROM $3
	`, m.gate.cfg.ModelHasRolesTable, m.gate.cfg.RolesTable)

	rows, err := m.gate.db.QueryContext(ctx, query, m.modelType, m.modelID, m.teamID)
	if err != nil {
		return nil, fmt.Errorf("wpd-gogate: get model roles: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var roles []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("wpd-gogate: scan model role: %w", err)
		}
		roles = append(roles, name)
	}

	return roles, rows.Err()
}

// GetDirectPermissions returns the names of all direct permissions assigned to the model.
func (m *ModelRef) GetDirectPermissions(ctx context.Context) ([]string, error) {
	query := fmt.Sprintf(`
		SELECT p.name FROM %s mhp
		JOIN %s p ON p.id = mhp.permission_id
		WHERE mhp.model_type = $1 AND mhp.model_id = $2 AND mhp.team_id IS NOT DISTINCT FROM $3
	`, m.gate.cfg.ModelHasPermissionsTable, m.gate.cfg.PermissionsTable)

	rows, err := m.gate.db.QueryContext(ctx, query, m.modelType, m.modelID, m.teamID)
	if err != nil {
		return nil, fmt.Errorf("wpd-gogate: get direct permissions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var permissions []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("wpd-gogate: scan direct permission: %w", err)
		}
		permissions = append(permissions, name)
	}

	return permissions, rows.Err()
}

// GetPermissionsViaRoles returns all permissions inherited by the model's roles.
func (m *ModelRef) GetPermissionsViaRoles(ctx context.Context) ([]string, error) {
	roles, err := m.GetRoleNames(ctx)
	if err != nil {
		return nil, err
	}

	m.gate.mu.RLock()
	defer m.gate.mu.RUnlock()

	permSet := make(map[string]bool)
	for _, r := range roles {
		if perms, ok := m.gate.rolePermissions[r]; ok {
			for p := range perms {
				permSet[p] = true
			}
		}
	}

	var permissions []string
	for p := range permSet {
		permissions = append(permissions, p)
	}

	return permissions, nil
}

// GetAllPermissions returns both direct and inherited permissions.
func (m *ModelRef) GetAllPermissions(ctx context.Context) ([]string, error) {
	direct, err := m.GetDirectPermissions(ctx)
	if err != nil {
		return nil, err
	}

	inherited, err := m.GetPermissionsViaRoles(ctx)
	if err != nil {
		return nil, err
	}

	permSet := make(map[string]bool)
	for _, p := range direct {
		permSet[p] = true
	}
	for _, p := range inherited {
		permSet[p] = true
	}

	var permissions []string
	for p := range permSet {
		permissions = append(permissions, p)
	}

	return permissions, nil
}
