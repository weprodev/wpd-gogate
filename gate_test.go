package gogate

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestGate_LoadPolicy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)

	// Mock the query that loads role-permission associations
	mock.ExpectQuery(`SELECT r.name, p.name FROM role_has_permissions rhp JOIN roles r ON r.id = rhp.role_id JOIN permissions p ON p.id = rhp.permission_id`).
		WillReturnRows(sqlmock.NewRows([]string{"role_name", "permission_name"}).
			AddRow("admin", "create:templates").
			AddRow("admin", "delete:templates").
			AddRow("member", "read:templates"),
		)

	if err := gate.LoadPolicy(context.Background()); err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}

	// Verify the in-memory cache
	if !gate.HasRolePermission("admin", "create:templates") {
		t.Error("expected admin to have create:templates")
	}
	if !gate.HasRolePermission("admin", "delete:templates") {
		t.Error("expected admin to have delete:templates")
	}
	if gate.HasRolePermission("admin", "read:templates") {
		t.Error("did not expect admin to have read:templates")
	}
	if !gate.HasRolePermission("member", "read:templates") {
		t.Error("expected member to have read:templates")
	}
	if gate.HasRolePermission("nonexistent", "read:templates") {
		t.Error("did not expect nonexistent role to have read:templates")
	}
}

func TestGate_Check(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	gate.rolePermissions = map[string]map[string]bool{
		"admin": {
			"create:templates": true,
		},
		"writer": {
			"create:articles": true,
		},
		"viewer": {
			"read:articles": true,
		},
	}

	modelType := "users"
	modelID := "user-uuid-1"
	teamID := "team-uuid-1"
	permission := "create:templates"

	t.Run("Direct Permission Match", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 'role' AS type, r.name AS value FROM model_has_roles mhr JOIN roles r ON r.id = mhr.role_id WHERE mhr.model_type = \$1 AND mhr.model_id = \$2 AND mhr.team_id IS NOT DISTINCT FROM \$3 UNION ALL SELECT 'permission' AS type, p.name AS value FROM model_has_permissions mhp JOIN permissions p ON p.id = mhp.permission_id WHERE mhp.model_type = \$1 AND mhp.model_id = \$2 AND mhp.team_id IS NOT DISTINCT FROM \$3 AND p.name = \$4`).
			WithArgs(modelType, modelID, teamID, permission).
			WillReturnRows(sqlmock.NewRows([]string{"type", "value"}).AddRow("permission", permission))

		allowed, err := gate.Check(context.Background(), modelType, modelID, permission, teamID)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if !allowed {
			t.Error("expected check to be allowed via direct permission")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("Role Permission Match", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 'role' AS type, r.name AS value FROM model_has_roles mhr JOIN roles r ON r.id = mhr.role_id WHERE mhr.model_type = \$1 AND mhr.model_id = \$2 AND mhr.team_id IS NOT DISTINCT FROM \$3 UNION ALL SELECT 'permission' AS type, p.name AS value FROM model_has_permissions mhp JOIN permissions p ON p.id = mhp.permission_id WHERE mhp.model_type = \$1 AND mhp.model_id = \$2 AND mhp.team_id IS NOT DISTINCT FROM \$3 AND p.name = \$4`).
			WithArgs(modelType, modelID, teamID, permission).
			WillReturnRows(sqlmock.NewRows([]string{"type", "value"}).AddRow("role", "admin"))

		allowed, err := gate.Check(context.Background(), modelType, modelID, permission, teamID)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if !allowed {
			t.Error("expected check to be allowed via admin role")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("Access Denied", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 'role' AS type, r.name AS value FROM model_has_roles mhr JOIN roles r ON r.id = mhr.role_id WHERE mhr.model_type = \$1 AND mhr.model_id = \$2 AND mhr.team_id IS NOT DISTINCT FROM \$3 UNION ALL SELECT 'permission' AS type, p.name AS value FROM model_has_permissions mhp JOIN permissions p ON p.id = mhp.permission_id WHERE mhp.model_type = \$1 AND mhp.model_id = \$2 AND mhp.team_id IS NOT DISTINCT FROM \$3 AND p.name = \$4`).
			WithArgs(modelType, modelID, teamID, permission).
			WillReturnRows(sqlmock.NewRows([]string{"type", "value"}).AddRow("role", "guest"))

		allowed, err := gate.Check(context.Background(), modelType, modelID, permission, teamID)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}
		if allowed {
			t.Error("expected check to be denied")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("Multi-Workspace Role Isolation", func(t *testing.T) {
		workspaceA := "workspace-A"
		workspaceB := "workspace-B"
		permCreate := "create:articles"

		// 1. Query for workspace A should look up roles scoped to workspace A
		mock.ExpectQuery(`SELECT 'role' AS type, r.name AS value FROM model_has_roles mhr JOIN roles r ON r.id = mhr.role_id WHERE mhr.model_type = \$1 AND mhr.model_id = \$2 AND mhr.team_id IS NOT DISTINCT FROM \$3 UNION ALL SELECT 'permission' AS type, p.name AS value FROM model_has_permissions mhp JOIN permissions p ON p.id = mhp.permission_id WHERE mhp.model_type = \$1 AND mhp.model_id = \$2 AND mhp.team_id IS NOT DISTINCT FROM \$3 AND p.name = \$4`).
			WithArgs(modelType, modelID, workspaceA, permCreate).
			WillReturnRows(sqlmock.NewRows([]string{"type", "value"}).AddRow("role", "writer"))

		// 2. Query for workspace B should look up roles scoped to workspace B
		mock.ExpectQuery(`SELECT 'role' AS type, r.name AS value FROM model_has_roles mhr JOIN roles r ON r.id = mhr.role_id WHERE mhr.model_type = \$1 AND mhr.model_id = \$2 AND mhr.team_id IS NOT DISTINCT FROM \$3 UNION ALL SELECT 'permission' AS type, p.name AS value FROM model_has_permissions mhp JOIN permissions p ON p.id = mhp.permission_id WHERE mhp.model_type = \$1 AND mhp.model_id = \$2 AND mhp.team_id IS NOT DISTINCT FROM \$3 AND p.name = \$4`).
			WithArgs(modelType, modelID, workspaceB, permCreate).
			WillReturnRows(sqlmock.NewRows([]string{"type", "value"}).AddRow("role", "viewer"))

		// Check workspace A (should be allowed via writer role)
		allowedA, err := gate.Check(context.Background(), modelType, modelID, permCreate, workspaceA)
		if err != nil {
			t.Fatalf("Check failed for workspace A: %v", err)
		}
		if !allowedA {
			t.Error("expected check to be allowed in workspace A (writer)")
		}

		// Check workspace B (should be denied since viewer doesn't have create:articles)
		allowedB, err := gate.Check(context.Background(), modelType, modelID, permCreate, workspaceB)
		if err != nil {
			t.Fatalf("Check failed for workspace B: %v", err)
		}
		if allowedB {
			t.Error("expected check to be denied in workspace B (viewer)")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestModelRef_AssignAndRemoveRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	user := gate.Model("users", "user-uuid", "team-uuid")

	t.Run("Assign Role Success", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles WHERE name = \$1 LIMIT 1`).
			WithArgs("admin").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("role-uuid-1"))

		mock.ExpectExec(`INSERT INTO model_has_roles \(role_id, model_type, model_id, team_id\) VALUES \(\$1, \$2, \$3, \$4\) ON CONFLICT \(role_id, model_id, model_type, team_id\) DO NOTHING`).
			WithArgs("role-uuid-1", "users", "user-uuid", "team-uuid").
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := user.AssignRole(context.Background(), "admin"); err != nil {
			t.Fatalf("AssignRole failed: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("Assign Role Nonexistent", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles WHERE name = \$1 LIMIT 1`).
			WithArgs("superadmin").
			WillReturnError(sql.ErrNoRows)

		err := user.AssignRole(context.Background(), "superadmin")
		if err == nil || !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("expected ErrNoRows, got %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("Remove Role", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles WHERE name = \$1 LIMIT 1`).
			WithArgs("admin").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("role-uuid-1"))

		mock.ExpectExec(`DELETE FROM model_has_roles WHERE role_id = \$1 AND model_type = \$2 AND model_id = \$3 AND team_id IS NOT DISTINCT FROM \$4`).
			WithArgs("role-uuid-1", "users", "user-uuid", "team-uuid").
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := user.RemoveRole(context.Background(), "admin"); err != nil {
			t.Fatalf("RemoveRole failed: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestModelRef_GiveAndRevokePermission(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	user := gate.Model("users", "user-uuid", "team-uuid")

	t.Run("Give Permission Success", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM permissions WHERE name = \$1 LIMIT 1`).
			WithArgs("edit:posts").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("permission-uuid-1"))

		mock.ExpectExec(`INSERT INTO model_has_permissions \(permission_id, model_type, model_id, team_id\) VALUES \(\$1, \$2, \$3, \$4\) ON CONFLICT \(permission_id, model_id, model_type, team_id\) DO NOTHING`).
			WithArgs("permission-uuid-1", "users", "user-uuid", "team-uuid").
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := user.GivePermissionTo(context.Background(), "edit:posts"); err != nil {
			t.Fatalf("GivePermissionTo failed: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("Revoke Permission", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM permissions WHERE name = \$1 LIMIT 1`).
			WithArgs("edit:posts").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("permission-uuid-1"))

		mock.ExpectExec(`DELETE FROM model_has_permissions WHERE permission_id = \$1 AND model_type = \$2 AND model_id = \$3 AND team_id IS NOT DISTINCT FROM \$4`).
			WithArgs("permission-uuid-1", "users", "user-uuid", "team-uuid").
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := user.RevokePermissionTo(context.Background(), "edit:posts"); err != nil {
			t.Fatalf("RevokePermissionTo failed: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestRoleRef_GiveAndRevokePermission(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	role := gate.Role("admin")

	t.Run("Give Permission to Role", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles WHERE name = \$1 LIMIT 1`).
			WithArgs("admin").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("role-uuid-1"))

		mock.ExpectQuery(`SELECT id FROM permissions WHERE name = \$1 LIMIT 1`).
			WithArgs("edit:posts").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("permission-uuid-1"))

		mock.ExpectExec(`INSERT INTO role_has_permissions \(permission_id, role_id\) VALUES \(\$1, \$2\) ON CONFLICT \(permission_id, role_id\) DO NOTHING`).
			WithArgs("permission-uuid-1", "role-uuid-1").
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := role.GivePermissionTo(context.Background(), "edit:posts"); err != nil {
			t.Fatalf("GivePermissionTo failed: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}

		// Cache should be updated in memory instantly
		if !gate.HasRolePermission("admin", "edit:posts") {
			t.Error("expected cache to have edit:posts for admin role")
		}
	})

	t.Run("Revoke Permission from Role", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles WHERE name = \$1 LIMIT 1`).
			WithArgs("admin").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("role-uuid-1"))

		mock.ExpectQuery(`SELECT id FROM permissions WHERE name = \$1 LIMIT 1`).
			WithArgs("edit:posts").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("permission-uuid-1"))

		mock.ExpectExec(`DELETE FROM role_has_permissions WHERE permission_id = \$1 AND role_id = \$2`).
			WithArgs("permission-uuid-1", "role-uuid-1").
			WillReturnResult(sqlmock.NewResult(1, 1))

		if err := role.RevokePermissionTo(context.Background(), "edit:posts"); err != nil {
			t.Fatalf("RevokePermissionTo failed: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}

		// Cache should be removed in memory instantly
		if gate.HasRolePermission("admin", "edit:posts") {
			t.Error("expected cache NOT to have edit:posts for admin role anymore")
		}
	})
}

func TestModelRef_ListingHelpers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	gate.rolePermissions = map[string]map[string]bool{
		"writer": {
			"edit:articles": true,
		},
		"editor": {
			"publish:articles": true,
		},
	}

	user := gate.Model("users", "user-uuid", "team-uuid")

	t.Run("GetRoleNames", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.name FROM model_has_roles mhr JOIN roles r ON r.id = mhr.role_id WHERE mhr.model_type = \$1 AND mhr.model_id = \$2 AND mhr.team_id IS NOT DISTINCT FROM \$3`).
			WithArgs("users", "user-uuid", "team-uuid").
			WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("writer").AddRow("editor"))

		roles, err := user.GetRoleNames(context.Background())
		if err != nil {
			t.Fatalf("GetRoleNames failed: %v", err)
		}

		expected := []string{"writer", "editor"}
		if !reflect.DeepEqual(roles, expected) {
			t.Errorf("expected %v, got %v", expected, roles)
		}
	})

	t.Run("GetDirectPermissions", func(t *testing.T) {
		mock.ExpectQuery(`SELECT p.name FROM model_has_permissions mhp JOIN permissions p ON p.id = mhp.permission_id WHERE mhp.model_type = \$1 AND mhp.model_id = \$2 AND mhp.team_id IS NOT DISTINCT FROM \$3`).
			WithArgs("users", "user-uuid", "team-uuid").
			WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin:override"))

		perms, err := user.GetDirectPermissions(context.Background())
		if err != nil {
			t.Fatalf("GetDirectPermissions failed: %v", err)
		}

		expected := []string{"admin:override"}
		if !reflect.DeepEqual(perms, expected) {
			t.Errorf("expected %v, got %v", expected, perms)
		}
	})

	t.Run("GetPermissionsViaRoles", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.name FROM model_has_roles mhr JOIN roles r ON r.id = mhr.role_id WHERE mhr.model_type = \$1 AND mhr.model_id = \$2 AND mhr.team_id IS NOT DISTINCT FROM \$3`).
			WithArgs("users", "user-uuid", "team-uuid").
			WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("writer").AddRow("editor"))

		perms, err := user.GetPermissionsViaRoles(context.Background())
		if err != nil {
			t.Fatalf("GetPermissionsViaRoles failed: %v", err)
		}

		permMap := make(map[string]bool)
		for _, p := range perms {
			permMap[p] = true
		}

		if !permMap["edit:articles"] || !permMap["publish:articles"] || len(perms) != 2 {
			t.Errorf("expected [edit:articles, publish:articles], got %v", perms)
		}
	})

	t.Run("GetAllPermissions", func(t *testing.T) {
		// Direct permissions
		mock.ExpectQuery(`SELECT p.name FROM model_has_permissions mhp JOIN permissions p ON p.id = mhp.permission_id WHERE mhp.model_type = \$1 AND mhp.model_id = \$2 AND mhp.team_id IS NOT DISTINCT FROM \$3`).
			WithArgs("users", "user-uuid", "team-uuid").
			WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin:override"))

		// Roles
		mock.ExpectQuery(`SELECT r.name FROM model_has_roles mhr JOIN roles r ON r.id = mhr.role_id WHERE mhr.model_type = \$1 AND mhr.model_id = \$2 AND mhr.team_id IS NOT DISTINCT FROM \$3`).
			WithArgs("users", "user-uuid", "team-uuid").
			WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("writer"))

		perms, err := user.GetAllPermissions(context.Background())
		if err != nil {
			t.Fatalf("GetAllPermissions failed: %v", err)
		}

		permMap := make(map[string]bool)
		for _, p := range perms {
			permMap[p] = true
		}

		if !permMap["admin:override"] || !permMap["edit:articles"] || len(perms) != 2 {
			t.Errorf("expected [admin:override, edit:articles], got %v", perms)
		}
	})
}
