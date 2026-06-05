package gogate

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

func TestIntegration_Postgres(t *testing.T) {
	host := os.Getenv("TEST_DB_HOST")
	if host == "" {
		t.Skip("Skipping integration test; TEST_DB_HOST not set")
	}

	port := os.Getenv("TEST_DB_PORT")
	if port == "" {
		port = "54322"
	}
	user := os.Getenv("TEST_DB_USER")
	if user == "" {
		user = "test_user"
	}
	password := os.Getenv("TEST_DB_PASSWORD")
	if password == "" {
		password = "test_password"
	}
	dbname := os.Getenv("TEST_DB_NAME")
	if dbname == "" {
		dbname = "test_gogate"
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close() //nolint:errcheck

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to ping database: %v", err)
	}

	ctx := context.Background()

	// 1. Setup prerequisite extensions and clean up tables
	_, err = db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto;`)
	if err != nil {
		t.Logf("Warning: failed to create pgcrypto extension (might already exist or be restricted): %v", err)
	}

	// Clean up table structures in reverse order to avoid dependency errors
	_, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS model_has_permissions;")
	_, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS model_has_roles;")
	_, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS role_has_permissions;")
	_, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS permissions;")
	_, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS roles;")

	// 2. Read and run migrations/create_permission_tables.up.sql
	migrationUp, err := os.ReadFile("migrations/create_permission_tables.up.sql")
	if err != nil {
		t.Fatalf("failed to read migration up file: %v", err)
	}

	_, err = db.ExecContext(ctx, string(migrationUp))
	if err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Defer teardown
	defer func() {
		migrationDown, err := os.ReadFile("migrations/create_permission_tables.down.sql")
		if err == nil {
			_, _ = db.ExecContext(ctx, string(migrationDown))
		}
	}()

	// 3. Initialize Gate
	gate := NewGate(db, nil)

	// Create roles
	err = gate.CreateRole(ctx, "editor", "web")
	if err != nil {
		t.Fatalf("failed to create role editor: %v", err)
	}
	err = gate.CreateRole(ctx, "viewer", "web")
	if err != nil {
		t.Fatalf("failed to create role viewer: %v", err)
	}
	err = gate.CreateRole(ctx, "writer", "web")
	if err != nil {
		t.Fatalf("failed to create role writer: %v", err)
	}

	// Create permissions
	err = gate.CreatePermission(ctx, "publish:articles", "web")
	if err != nil {
		t.Fatalf("failed to create permission publish:articles: %v", err)
	}
	err = gate.CreatePermission(ctx, "read:articles", "web")
	if err != nil {
		t.Fatalf("failed to create permission read:articles: %v", err)
	}
	err = gate.CreatePermission(ctx, "create:articles", "web")
	if err != nil {
		t.Fatalf("failed to create permission create:articles: %v", err)
	}
	err = gate.CreatePermission(ctx, "admin:settings", "web")
	if err != nil {
		t.Fatalf("failed to create permission admin:settings: %v", err)
	}

	// Load empty policies into memory cache
	if err := gate.LoadPolicy(ctx); err != nil {
		t.Fatalf("failed to load initial policies: %v", err)
	}

	// Associate permissions with roles
	editorRole := gate.Role("editor")
	err = editorRole.GivePermissionTo(ctx, "publish:articles")
	if err != nil {
		t.Fatalf("failed to assign publish:articles to editor: %v", err)
	}
	err = editorRole.GivePermissionTo(ctx, "read:articles")
	if err != nil {
		t.Fatalf("failed to assign read:articles to editor: %v", err)
	}

	viewerRole := gate.Role("viewer")
	err = viewerRole.GivePermissionTo(ctx, "read:articles")
	if err != nil {
		t.Fatalf("failed to assign read:articles to viewer: %v", err)
	}

	writerRole := gate.Role("writer")
	err = writerRole.GivePermissionTo(ctx, "create:articles")
	if err != nil {
		t.Fatalf("failed to assign create:articles to writer: %v", err)
	}

	// Verify local cache updates
	if !gate.HasRolePermission("editor", "publish:articles") {
		t.Error("expected editor to have publish:articles in cache")
	}
	if !gate.HasRolePermission("editor", "read:articles") {
		t.Error("expected editor to have read:articles in cache")
	}
	if !gate.HasRolePermission("writer", "create:articles") {
		t.Error("expected writer to have create:articles in cache")
	}
	if gate.HasRolePermission("viewer", "publish:articles") {
		t.Error("viewer should not have publish:articles in cache")
	}

	// Setup users and teams (UUIDs)
	userID := "00000000-0000-0000-0000-000000000010"
	teamID := "00000000-0000-0000-0000-000000000001"
	otherTeamID := "00000000-0000-0000-0000-000000000002"

	userInTeam := gate.Model("users", userID, teamID)

	// Check initially has no access
	ok, err := userInTeam.Can(ctx, "read:articles")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if ok {
		t.Error("expected user to not have read:articles access initially")
	}

	// Assign viewer role in teamID
	err = userInTeam.AssignRole(ctx, "viewer")
	if err != nil {
		t.Fatalf("failed to assign viewer role: %v", err)
	}

	// Verify access allowed
	ok, err = userInTeam.Can(ctx, "read:articles")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if !ok {
		t.Error("expected user to have read:articles access as viewer")
	}

	// Verify check is scoped to teamID (checking otherTeamID should return false)
	userInOtherTeam := gate.Model("users", userID, otherTeamID)
	ok, err = userInOtherTeam.Can(ctx, "read:articles")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if ok {
		t.Error("user should not have read:articles access in otherTeamID")
	}

	// Test case: Fully isolated multi-workspace roles (writer in Team A, viewer in Team B)
	userTeamA := gate.Model("users", userID, teamID)
	err = userTeamA.AssignRole(ctx, "writer")
	if err != nil {
		t.Fatalf("failed to assign writer role in Team A: %v", err)
	}
	userTeamB := gate.Model("users", userID, otherTeamID)
	err = userTeamB.AssignRole(ctx, "viewer")
	if err != nil {
		t.Fatalf("failed to assign viewer role in Team B: %v", err)
	}

	// In Team A (writer role assigned), user has create:articles
	ok, err = userTeamA.Can(ctx, "create:articles")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if !ok {
		t.Error("expected user to have create:articles access in Team A (writer)")
	}

	// In Team B (viewer role assigned), user has read:articles but NOT create:articles
	ok, err = userTeamB.Can(ctx, "read:articles")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if !ok {
		t.Error("expected user to have read:articles access in Team B (viewer)")
	}
	ok, err = userTeamB.Can(ctx, "create:articles")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if ok {
		t.Error("user should not have create:articles access in Team B (viewer)")
	}

	// Clean up Team A's writer role and Team B's viewer role
	err = userTeamA.RemoveRole(ctx, "writer")
	if err != nil {
		t.Fatalf("failed to remove writer role from Team A: %v", err)
	}
	err = userTeamB.RemoveRole(ctx, "viewer")
	if err != nil {
		t.Fatalf("failed to remove viewer role from Team B: %v", err)
	}

	// Give direct permission override in teamID
	err = userInTeam.GivePermissionTo(ctx, "admin:settings")
	if err != nil {
		t.Fatalf("failed to give direct permission: %v", err)
	}

	// Verify direct permission works
	ok, err = userInTeam.Can(ctx, "admin:settings")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if !ok {
		t.Error("expected user to have direct admin:settings access")
	}

	// Verify other team has no direct permission
	ok, err = userInOtherTeam.Can(ctx, "admin:settings")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if ok {
		t.Error("user should not have admin:settings access in otherTeamID")
	}

	// Revoke direct permission
	err = userInTeam.RevokePermissionTo(ctx, "admin:settings")
	if err != nil {
		t.Fatalf("failed to revoke direct permission: %v", err)
	}

	// Verify direct permission revoked
	ok, err = userInTeam.Can(ctx, "admin:settings")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if ok {
		t.Error("expected direct admin:settings access to be revoked")
	}

	// Revoke role viewer
	err = userInTeam.RemoveRole(ctx, "viewer")
	if err != nil {
		t.Fatalf("failed to remove role: %v", err)
	}

	// Verify role revoked
	ok, err = userInTeam.Can(ctx, "read:articles")
	if err != nil {
		t.Fatalf("Can failed: %v", err)
	}
	if ok {
		t.Error("expected read:articles access to be revoked after role removal")
	}
}
