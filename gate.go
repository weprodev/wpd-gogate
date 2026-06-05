package gogate

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// DBTX is the minimal database interface required by wpd-gogate.
// It is satisfied by *sql.DB and *sql.Tx.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Config defines the table names and defaults for the RBAC gate,
// mirroring standard relational database RBAC conventions.
type Config struct {
	RolesTable               string
	PermissionsTable         string
	RoleHasPermissionsTable  string
	ModelHasRolesTable       string
	ModelHasPermissionsTable string
	DefaultGuardName         string
}

// DefaultConfig returns the standard config mapping to defaults.
func DefaultConfig() Config {
	return Config{
		RolesTable:               "roles",
		PermissionsTable:         "permissions",
		RoleHasPermissionsTable:  "role_has_permissions",
		ModelHasRolesTable:       "model_has_roles",
		ModelHasPermissionsTable: "model_has_permissions",
		DefaultGuardName:         "web",
	}
}

// Gate is the core engine for role-based and permission-based authorization.
type Gate struct {
	db              DBTX
	cfg             Config
	mu              sync.RWMutex
	rolePermissions map[string]map[string]bool // role_name -> permission_name -> true
}

// NewGate instantiates a new Gate with a DB client and optional configuration.
func NewGate(db DBTX, cfg *Config) *Gate {
	var c Config
	if cfg != nil {
		c = *cfg
	} else {
		c = DefaultConfig()
	}

	return &Gate{
		db:              db,
		cfg:             c,
		rolePermissions: make(map[string]map[string]bool),
	}
}

// LoadPolicy fetches all role-permission associations from the database
// and caches them in memory. This is thread-safe and should be run on boot
// or when permissions are updated.
func (g *Gate) LoadPolicy(ctx context.Context) error {
	query := fmt.Sprintf(`
		SELECT r.name, p.name
		FROM %s rhp
		JOIN %s r ON r.id = rhp.role_id
		JOIN %s p ON p.id = rhp.permission_id
	`, g.cfg.RoleHasPermissionsTable, g.cfg.RolesTable, g.cfg.PermissionsTable)

	rows, err := g.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("wpd-gogate: query role permissions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	// Temp map to construct the cache before swap
	newCache := make(map[string]map[string]bool)

	for rows.Next() {
		var roleName, permissionName string
		if err := rows.Scan(&roleName, &permissionName); err != nil {
			return fmt.Errorf("wpd-gogate: scan role permission row: %w", err)
		}

		if _, exists := newCache[roleName]; !exists {
			newCache[roleName] = make(map[string]bool)
		}
		newCache[roleName][permissionName] = true
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("wpd-gogate: read role permissions rows: %w", err)
	}

	// Update the cache under write lock
	g.mu.Lock()
	g.rolePermissions = newCache
	g.mu.Unlock()

	return nil
}

// HasRolePermission performs an in-memory O(1) check of whether a role
// is assigned a specific permission.
func (g *Gate) HasRolePermission(roleName, permissionName string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	permissions, exists := g.rolePermissions[roleName]
	if !exists {
		return false
	}
	return permissions[permissionName]
}

// Check verifies if the model (e.g. user) has the required permission.
// It queries both direct permissions and roles in a single database round-trip (UNION ALL),
// then maps them against the in-memory cache to determine access.
// teamID is optional and can be nil to check global assignments.
func (g *Gate) Check(ctx context.Context, modelType string, modelID any, permissionName string, teamID any) (bool, error) {
	query := fmt.Sprintf(`
		SELECT 'role' AS type, r.name AS value
		FROM %s mhr
		JOIN %s r ON r.id = mhr.role_id
		WHERE mhr.model_type = $1
		  AND mhr.model_id = $2
		  AND mhr.team_id IS NOT DISTINCT FROM $3
		UNION ALL
		SELECT 'permission' AS type, p.name AS value
		FROM %s mhp
		JOIN %s p ON p.id = mhp.permission_id
		WHERE mhp.model_type = $1
		  AND mhp.model_id = $2
		  AND mhp.team_id IS NOT DISTINCT FROM $3
		  AND p.name = $4
	`, g.cfg.ModelHasRolesTable, g.cfg.RolesTable, g.cfg.ModelHasPermissionsTable, g.cfg.PermissionsTable)

	rows, err := g.db.QueryContext(ctx, query, modelType, modelID, teamID, permissionName)
	if err != nil {
		return false, fmt.Errorf("wpd-gogate: query access records: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var recordType, value string
		if err := rows.Scan(&recordType, &value); err != nil {
			return false, fmt.Errorf("wpd-gogate: scan access record: %w", err)
		}

		if recordType == "permission" {
			// Direct permission matches the requested permissionName
			return true, nil
		}

		if recordType == "role" {
			// Check the in-memory cache for this role
			if g.HasRolePermission(value, permissionName) {
				return true, nil
			}
		}
	}

	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("wpd-gogate: read access records rows: %w", err)
	}

	return false, nil
}
