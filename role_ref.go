package gogate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// RoleRef provides a fluent API for managing a specific Role's permissions.
type RoleRef struct {
	gate *Gate
	name string
}

// Role constructs a RoleRef for role-scoped operations.
func (g *Gate) Role(name string) *RoleRef {
	return &RoleRef{
		gate: g,
		name: name,
	}
}

// GivePermissionTo assigns the specified permission to the role in the database
// and immediately updates the in-memory cache.
func (r *RoleRef) GivePermissionTo(ctx context.Context, permissionName string) error {
	// Get role ID
	queryRole := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 LIMIT 1", r.gate.cfg.RolesTable)
	var roleID string
	err := r.gate.db.QueryRowContext(ctx, queryRole, r.name).Scan(&roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("wpd-gogate: role %q not found: %w", r.name, err)
		}
		return fmt.Errorf("wpd-gogate: lookup role ID: %w", err)
	}

	// Get permission ID
	queryPermission := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 LIMIT 1", r.gate.cfg.PermissionsTable)
	var permissionID string
	err = r.gate.db.QueryRowContext(ctx, queryPermission, permissionName).Scan(&permissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("wpd-gogate: permission %q not found: %w", permissionName, err)
		}
		return fmt.Errorf("wpd-gogate: lookup permission ID: %w", err)
	}

	// Insert into join table
	queryInsert := fmt.Sprintf(`
		INSERT INTO %s (permission_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (permission_id, role_id) DO NOTHING
	`, r.gate.cfg.RoleHasPermissionsTable)

	_, err = r.gate.db.ExecContext(ctx, queryInsert, permissionID, roleID)
	if err != nil {
		return fmt.Errorf("wpd-gogate: associate permission to role: %w", err)
	}

	// Update the in-memory cache instantly (thread-safe)
	r.gate.mu.Lock()
	if r.gate.rolePermissions == nil {
		r.gate.rolePermissions = make(map[string]map[string]bool)
	}
	if _, ok := r.gate.rolePermissions[r.name]; !ok {
		r.gate.rolePermissions[r.name] = make(map[string]bool)
	}
	r.gate.rolePermissions[r.name][permissionName] = true
	r.gate.mu.Unlock()

	return nil
}

// RevokePermissionTo revokes the specified permission from the role
// and immediately removes it from the in-memory cache.
func (r *RoleRef) RevokePermissionTo(ctx context.Context, permissionName string) error {
	// Get role ID
	queryRole := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 LIMIT 1", r.gate.cfg.RolesTable)
	var roleID string
	err := r.gate.db.QueryRowContext(ctx, queryRole, r.name).Scan(&roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // Role doesn't exist, nothing to revoke
		}
		return fmt.Errorf("wpd-gogate: lookup role ID: %w", err)
	}

	// Get permission ID
	queryPermission := fmt.Sprintf("SELECT id FROM %s WHERE name = $1 LIMIT 1", r.gate.cfg.PermissionsTable)
	var permissionID string
	err = r.gate.db.QueryRowContext(ctx, queryPermission, permissionName).Scan(&permissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // Permission doesn't exist, nothing to revoke
		}
		return fmt.Errorf("wpd-gogate: lookup permission ID: %w", err)
	}

	// Delete from join table
	queryDelete := fmt.Sprintf(`
		DELETE FROM %s WHERE permission_id = $1 AND role_id = $2
	`, r.gate.cfg.RoleHasPermissionsTable)

	_, err = r.gate.db.ExecContext(ctx, queryDelete, permissionID, roleID)
	if err != nil {
		return fmt.Errorf("wpd-gogate: revoke permission from role: %w", err)
	}

	// Remove from in-memory cache instantly
	r.gate.mu.Lock()
	if r.gate.rolePermissions != nil {
		if perms, ok := r.gate.rolePermissions[r.name]; ok {
			delete(perms, permissionName)
		}
	}
	r.gate.mu.Unlock()

	return nil
}

// GetPermissionNames returns names of all permissions assigned to the role.
func (r *RoleRef) GetPermissionNames(ctx context.Context) ([]string, error) {
	r.gate.mu.RLock()
	defer r.gate.mu.RUnlock()

	var permissions []string
	if perms, ok := r.gate.rolePermissions[r.name]; ok {
		for p := range perms {
			permissions = append(permissions, p)
		}
	}

	return permissions, nil
}
