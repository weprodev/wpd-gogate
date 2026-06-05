package gogate

import (
	"context"
	"fmt"
)

// CreateRole inserts a new role into the database.
func (g *Gate) CreateRole(ctx context.Context, name string, guardName string) error {
	if guardName == "" {
		guardName = g.cfg.DefaultGuardName
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (name, guard_name)
		VALUES ($1, $2)
		ON CONFLICT (name, guard_name) DO NOTHING
	`, g.cfg.RolesTable)

	_, err := g.db.ExecContext(ctx, query, name, guardName)
	if err != nil {
		return fmt.Errorf("wpd-gogate: create role %q: %w", name, err)
	}

	return nil
}

// CreatePermission inserts a new permission into the database.
func (g *Gate) CreatePermission(ctx context.Context, name string, guardName string) error {
	if guardName == "" {
		guardName = g.cfg.DefaultGuardName
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (name, guard_name)
		VALUES ($1, $2)
		ON CONFLICT (name, guard_name) DO NOTHING
	`, g.cfg.PermissionsTable)

	_, err := g.db.ExecContext(ctx, query, name, guardName)
	if err != nil {
		return fmt.Errorf("wpd-gogate: create permission %q: %w", name, err)
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
