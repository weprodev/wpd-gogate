package gogate

import (
	"context"
	"fmt"
)

// CreateRole inserts a new role into the database.
func (g *Gate) CreateRole(ctx context.Context, name string, guardName string) error {
	guardName = g.resolveGuardName(guardName)

	query := fmt.Sprintf(`
		INSERT INTO %s (name, guard_name)
		VALUES ($1, $2)
		ON CONFLICT (name, guard_name) DO NOTHING
	`, g.cfg.RolesTable)

	res, err := g.db.ExecContext(ctx, query, name, guardName)
	if err != nil {
		return fmt.Errorf("wpd-gogate: create role %q: %w", name, err)
	}

	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		return ErrRoleAlreadyExists
	}

	return nil
}

// CreatePermission inserts a new permission into the database.
func (g *Gate) CreatePermission(ctx context.Context, name string, guardName string) error {
	guardName = g.resolveGuardName(guardName)

	query := fmt.Sprintf(`
		INSERT INTO %s (name, guard_name)
		VALUES ($1, $2)
		ON CONFLICT (name, guard_name) DO NOTHING
	`, g.cfg.PermissionsTable)

	res, err := g.db.ExecContext(ctx, query, name, guardName)
	if err != nil {
		return fmt.Errorf("wpd-gogate: create permission %q: %w", name, err)
	}

	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		return ErrPermissionAlreadyExists
	}

	return nil
}

// DeleteRole deletes a role from the database and removes it from the cache.
func (g *Gate) DeleteRole(ctx context.Context, name string) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE name = $1", g.cfg.RolesTable)
	_, err := g.db.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("wpd-gogate: delete role %q: %w", name, err)
	}

	// Update the cache instantly
	g.mu.Lock()
	delete(g.rolePermissions, name)
	g.mu.Unlock()

	return nil
}

// DeletePermission deletes a permission from the database and removes it from all roles in the cache.
func (g *Gate) DeletePermission(ctx context.Context, name string) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE name = $1", g.cfg.PermissionsTable)
	_, err := g.db.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("wpd-gogate: delete permission %q: %w", name, err)
	}

	// Update the cache instantly
	g.mu.Lock()
	for role := range g.rolePermissions {
		delete(g.rolePermissions[role], name)
	}
	g.mu.Unlock()

	return nil
}

// GetAllRolesMap returns all roles in the database, grouped by guard_name.
func (g *Gate) GetAllRolesMap(ctx context.Context) (map[string][]string, error) {
	query := fmt.Sprintf("SELECT guard_name, name FROM %s", g.cfg.RolesTable)
	rows, err := g.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("wpd-gogate: get all roles: %w", err)
	}
	defer rows.Close()

	rolesMap := make(map[string][]string)
	for rows.Next() {
		var guardName, name string
		if err := rows.Scan(&guardName, &name); err != nil {
			return nil, fmt.Errorf("wpd-gogate: scan role row: %w", err)
		}
		rolesMap[guardName] = append(rolesMap[guardName], name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("wpd-gogate: read role rows: %w", err)
	}
	return rolesMap, nil
}

// GetAllPermissionsMap returns all permissions in the database, grouped by guard_name.
func (g *Gate) GetAllPermissionsMap(ctx context.Context) (map[string][]string, error) {
	query := fmt.Sprintf("SELECT guard_name, name FROM %s", g.cfg.PermissionsTable)
	rows, err := g.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("wpd-gogate: get all permissions: %w", err)
	}
	defer rows.Close()

	permsMap := make(map[string][]string)
	for rows.Next() {
		var guardName, name string
		if err := rows.Scan(&guardName, &name); err != nil {
			return nil, fmt.Errorf("wpd-gogate: scan permission row: %w", err)
		}
		permsMap[guardName] = append(permsMap[guardName], name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("wpd-gogate: read permission rows: %w", err)
	}
	return permsMap, nil
}
