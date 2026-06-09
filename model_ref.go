package gogate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
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
func (m *ModelRef) Can(ctx context.Context, permissionName string, guardName string) (bool, error) {
	guardName = m.gate.resolveGuardName(guardName)
	return m.gate.Check(ctx, m.modelType, m.modelID, permissionName, guardName, m.teamID)
}

// AssignRole assigns the given role to the model.
func (m *ModelRef) AssignRole(ctx context.Context, roleName string, guardName string) error {
	guardName = m.gate.resolveGuardName(guardName)
	// First get the role ID
	queryRole := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 AND guard_name = $2 LIMIT 1", m.gate.cfg.RolesTable)
	var roleID string
	err := m.gate.db.QueryRowContext(ctx, queryRole, roleName, guardName).Scan(&roleID)
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
func (m *ModelRef) RemoveRole(ctx context.Context, roleName string, guardName string) error {
	guardName = m.gate.resolveGuardName(guardName)
	// First get the role ID
	queryRole := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 AND guard_name = $2 LIMIT 1", m.gate.cfg.RolesTable)
	var roleID string
	err := m.gate.db.QueryRowContext(ctx, queryRole, roleName, guardName).Scan(&roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // Role doesn't exist, so nothing to remove
		}
		return fmt.Errorf("wpd-gogate: lookup role ID: %w", err)
	}

	cond, teamArgs := m.buildTeamCondition("team_id", 4)
	queryDelete := fmt.Sprintf(`
		DELETE FROM %s
		WHERE role_id = $1 AND model_type = $2 AND model_id = $3 AND %s
	`, m.gate.cfg.ModelHasRolesTable, cond)
	args := append([]any{roleID, m.modelType, m.modelID}, teamArgs...)

	_, err = m.gate.db.ExecContext(ctx, queryDelete, args...)
	if err != nil {
		return fmt.Errorf("wpd-gogate: remove role from model: %w", err)
	}

	return nil
}

// GivePermissionTo assigns a direct permission override to the model.
func (m *ModelRef) GivePermissionTo(ctx context.Context, permissionName string, guardName string) error {
	guardName = m.gate.resolveGuardName(guardName)
	// Get the permission ID
	queryPermission := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 AND guard_name = $2 LIMIT 1", m.gate.cfg.PermissionsTable)
	var permissionID string
	err := m.gate.db.QueryRowContext(ctx, queryPermission, permissionName, guardName).Scan(&permissionID)
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
func (m *ModelRef) RevokePermissionTo(ctx context.Context, permissionName string, guardName string) error {
	guardName = m.gate.resolveGuardName(guardName)
	queryPermission := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 AND guard_name = $2 LIMIT 1", m.gate.cfg.PermissionsTable)
	var permissionID string
	err := m.gate.db.QueryRowContext(ctx, queryPermission, permissionName, guardName).Scan(&permissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // Permission doesn't exist, so nothing to revoke
		}
		return fmt.Errorf("wpd-gogate: lookup permission ID: %w", err)
	}

	cond, teamArgs := m.buildTeamCondition("team_id", 4)
	queryDelete := fmt.Sprintf(`
		DELETE FROM %s
		WHERE permission_id = $1 AND model_type = $2 AND model_id = $3 AND %s
	`, m.gate.cfg.ModelHasPermissionsTable, cond)
	args := append([]any{permissionID, m.modelType, m.modelID}, teamArgs...)

	_, err = m.gate.db.ExecContext(ctx, queryDelete, args...)
	if err != nil {
		return fmt.Errorf("wpd-gogate: revoke permission from model: %w", err)
	}

	return nil
}

// GetRoleNames returns the names of all roles assigned to the model.
func (m *ModelRef) GetRoleNames(ctx context.Context) ([]string, error) {
	cond, teamArgs := m.buildTeamCondition("mhr.team_id", 3)
	query := fmt.Sprintf(`
		SELECT r.name FROM %s mhr
		JOIN %s r ON r.id = mhr.role_id
		WHERE mhr.model_type = $1 AND mhr.model_id = $2 AND %s
	`, m.gate.cfg.ModelHasRolesTable, m.gate.cfg.RolesTable, cond)
	args := append([]any{m.modelType, m.modelID}, teamArgs...)

	rows, err := m.gate.db.QueryContext(ctx, query, args...)
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

// GetRolesMap returns all roles assigned to the model, grouped by guard_name.
func (m *ModelRef) GetRolesMap(ctx context.Context) (map[string][]string, error) {
	cond, teamArgs := m.buildTeamCondition("mhr.team_id", 3)
	query := fmt.Sprintf(`
		SELECT r.name, r.guard_name FROM %s mhr
		JOIN %s r ON r.id = mhr.role_id
		WHERE mhr.model_type = $1 AND mhr.model_id = $2 AND %s
	`, m.gate.cfg.ModelHasRolesTable, m.gate.cfg.RolesTable, cond)
	args := append([]any{m.modelType, m.modelID}, teamArgs...)

	rows, err := m.gate.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("wpd-gogate: get model roles map: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	rolesMap := make(map[string][]string)
	for rows.Next() {
		var name, guardName string
		if err := rows.Scan(&name, &guardName); err != nil {
			return nil, fmt.Errorf("wpd-gogate: scan model role map: %w", err)
		}
		rolesMap[guardName] = append(rolesMap[guardName], name)
	}

	return rolesMap, rows.Err()
}

// GetDirectPermissions returns the names of all direct permissions assigned to the model.
func (m *ModelRef) GetDirectPermissions(ctx context.Context) ([]string, error) {
	cond, teamArgs := m.buildTeamCondition("mhp.team_id", 3)
	query := fmt.Sprintf(`
		SELECT p.name FROM %s mhp
		JOIN %s p ON p.id = mhp.permission_id
		WHERE mhp.model_type = $1 AND mhp.model_id = $2 AND %s
	`, m.gate.cfg.ModelHasPermissionsTable, m.gate.cfg.PermissionsTable, cond)
	args := append([]any{m.modelType, m.modelID}, teamArgs...)

	rows, err := m.gate.db.QueryContext(ctx, query, args...)
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

// HasRole checks if the model has the specified role directly in the database.
func (m *ModelRef) HasRole(ctx context.Context, roleName string, guardName string) (bool, error) {
	guardName = m.gate.resolveGuardName(guardName)
	cond, teamArgs := m.buildTeamCondition("mhr.team_id", 5)
	query := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %s mhr
			JOIN %s r ON r.id = mhr.role_id
			WHERE mhr.model_type = $1 AND mhr.model_id = $2 AND r.name = $3 AND r.guard_name = $4 AND %s
		)
	`, m.gate.cfg.ModelHasRolesTable, m.gate.cfg.RolesTable, cond)
	args := append([]any{m.modelType, m.modelID, roleName, guardName}, teamArgs...)

	var exists bool
	err := m.gate.db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("wpd-gogate: check user role %q: %w", roleName, err)
	}
	return exists, nil
}

// HasAnyRole checks if the model has at least one of the specified roles.
func (m *ModelRef) HasAnyRole(ctx context.Context, guardName string, roleNames ...string) (bool, error) {
	guardName = m.gate.resolveGuardName(guardName)
	if len(roleNames) == 0 {
		return false, nil
	}
	rolesMap, err := m.GetRolesMap(ctx)
	if err != nil {
		return false, err
	}

	assigned := rolesMap[guardName]

	roleMap := make(map[string]bool, len(assigned))
	for _, r := range assigned {
		roleMap[r] = true
	}
	for _, r := range roleNames {
		if roleMap[r] {
			return true, nil
		}
	}
	return false, nil
}

// HasAllRoles checks if the model has all of the specified roles.
func (m *ModelRef) HasAllRoles(ctx context.Context, guardName string, roleNames ...string) (bool, error) {
	guardName = m.gate.resolveGuardName(guardName)
	if len(roleNames) == 0 {
		return true, nil
	}
	rolesMap, err := m.GetRolesMap(ctx)
	if err != nil {
		return false, err
	}

	assigned := rolesMap[guardName]

	roleMap := make(map[string]bool, len(assigned))
	for _, r := range assigned {
		roleMap[r] = true
	}
	for _, r := range roleNames {
		if !roleMap[r] {
			return false, nil
		}
	}
	return true, nil
}

// HasAnyPermission checks if the model has any of the specified permissions.
func (m *ModelRef) HasAnyPermission(ctx context.Context, permissionNames ...string) (bool, error) {
	if len(permissionNames) == 0 {
		return false, nil
	}
	assigned, err := m.GetAllPermissions(ctx)
	if err != nil {
		return false, err
	}

	permMap := make(map[string]bool, len(assigned))
	for _, p := range assigned {
		permMap[p] = true
	}
	for _, p := range permissionNames {
		if permMap[p] {
			return true, nil
		}
	}
	return false, nil
}

// HasAllPermissions checks if the model has all of the specified permissions.
func (m *ModelRef) HasAllPermissions(ctx context.Context, permissionNames ...string) (bool, error) {
	if len(permissionNames) == 0 {
		return true, nil
	}
	assigned, err := m.GetAllPermissions(ctx)
	if err != nil {
		return false, err
	}

	permMap := make(map[string]bool, len(assigned))
	for _, p := range assigned {
		permMap[p] = true
	}
	for _, p := range permissionNames {
		if !permMap[p] {
			return false, nil
		}
	}
	return true, nil
}

// buildTeamCondition constructs the SQL fragment and arguments for filtering by team_id.
// It returns the WHERE clause fragment (e.g. "team_id IS NULL" or "team_id = $X") and
// the corresponding arguments to append to the query args.
func (m *ModelRef) buildTeamCondition(column string, paramIndex int) (string, []any) {
	if IsNilOrEmpty(m.teamID) {
		return column + " IS NULL", nil
	}
	return fmt.Sprintf("%s = $%d", column, paramIndex), []any{m.teamID}
}

// IsNilOrEmpty checks if a value is nil, an empty string, a nil pointer, or a zero UUID.
func IsNilOrEmpty(val any) bool {
	if val == nil {
		return true
	}

	rv := reflect.ValueOf(val)
	switch rv.Kind() {
	case reflect.String:
		return rv.String() == ""
	case reflect.Pointer:
		if rv.IsNil() {
			return true
		}
		return IsNilOrEmpty(rv.Elem().Interface())
	case reflect.Array:
		if rv.Len() == 16 {
			for i := 0; i < 16; i++ {
				if rv.Index(i).Uint() != 0 {
					return false
				}
			}
			return true
		}
	}
	return false
}
