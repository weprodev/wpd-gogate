package gogate

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestGate_ErrorPaths(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	ctx := context.Background()

	t.Run("LoadPolicy_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.guard_name`).WillReturnError(sql.ErrConnDone)
		err := gate.LoadPolicy(ctx)
		assert.Error(t, err)
	})

	t.Run("Check_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 'role' AS type`).WillReturnError(sql.ErrConnDone)
		_, err := gate.Check(ctx, "users", "1", "edit", "web", nil)
		assert.Error(t, err)
	})

	user := gate.Model("users", "1", nil)

	t.Run("AssignRole_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnError(sql.ErrConnDone)
		err := user.AssignRole(ctx, "admin", "web")
		assert.Error(t, err)

		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectExec(`INSERT INTO model_has_roles`).WillReturnError(sql.ErrConnDone)
		err = user.AssignRole(ctx, "admin", "web")
		assert.Error(t, err)
	})

	t.Run("RemoveRole_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnError(sql.ErrConnDone)
		err := user.RemoveRole(ctx, "admin", "web")
		assert.Error(t, err)

		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectExec(`DELETE FROM model_has_roles`).WillReturnError(sql.ErrConnDone)
		err = user.RemoveRole(ctx, "admin", "web")
		assert.Error(t, err)
	})

	t.Run("GivePermissionTo_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnError(sql.ErrConnDone)
		err := user.GivePermissionTo(ctx, "edit", "web")
		assert.Error(t, err)

		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectExec(`INSERT INTO model_has_permissions`).WillReturnError(sql.ErrConnDone)
		err = user.GivePermissionTo(ctx, "edit", "web")
		assert.Error(t, err)
	})

	t.Run("RevokePermissionTo_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnError(sql.ErrConnDone)
		err := user.RevokePermissionTo(ctx, "edit", "web")
		assert.Error(t, err)

		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectExec(`DELETE FROM model_has_permissions`).WillReturnError(sql.ErrConnDone)
		err = user.RevokePermissionTo(ctx, "edit", "web")
		assert.Error(t, err)
	})

	t.Run("GetRoleNames_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.name FROM model_has_roles`).WillReturnError(sql.ErrConnDone)
		_, err := user.GetRoleNames(ctx)
		assert.Error(t, err)
	})

	t.Run("GetRolesMap_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.guard_name, r.name FROM model_has_roles`).WillReturnError(sql.ErrConnDone)
		_, err := user.GetRolesMap(ctx)
		assert.Error(t, err)
	})

	t.Run("GetDirectPermissions_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT p.name FROM model_has_permissions`).WillReturnError(sql.ErrConnDone)
		_, err := user.GetDirectPermissions(ctx)
		assert.Error(t, err)
	})

	t.Run("GetPermissionsViaRoles_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.name FROM model_has_roles`).WillReturnError(sql.ErrConnDone)
		_, err := user.GetPermissionsViaRoles(ctx)
		assert.Error(t, err)
	})

	t.Run("GetAllPermissions_DBError1", func(t *testing.T) {
		mock.ExpectQuery(`SELECT p.name FROM model_has_permissions`).WillReturnError(sql.ErrConnDone)
		_, err := user.GetAllPermissions(ctx)
		assert.Error(t, err)
	})

	t.Run("GetAllPermissions_DBError2", func(t *testing.T) {
		mock.ExpectQuery(`SELECT p.name FROM model_has_permissions`).WillReturnRows(sqlmock.NewRows([]string{"name"}))
		mock.ExpectQuery(`SELECT r.name FROM model_has_roles`).WillReturnError(sql.ErrConnDone)
		_, err := user.GetAllPermissions(ctx)
		assert.Error(t, err)
	})

	t.Run("HasRole_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT EXISTS`).WillReturnError(sql.ErrConnDone)
		_, err := user.HasRole(ctx, "admin", "web")
		assert.Error(t, err)
	})

	t.Run("HasAnyRole_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.name, r.guard_name FROM model_has_roles`).WillReturnError(sql.ErrConnDone)
		_, err := user.HasAnyRole(ctx, "web", "admin")
		assert.Error(t, err)
	})

	t.Run("HasAllRoles_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.name, r.guard_name FROM model_has_roles`).WillReturnError(sql.ErrConnDone)
		_, err := user.HasAllRoles(ctx, "web", "admin")
		assert.Error(t, err)
	})

	t.Run("HasAnyPermission_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT p.name FROM model_has_permissions`).WillReturnError(sql.ErrConnDone)
		_, err := user.HasAnyPermission(ctx, "edit")
		assert.Error(t, err)
	})

	t.Run("HasAllPermissions_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT p.name FROM model_has_permissions`).WillReturnError(sql.ErrConnDone)
		_, err := user.HasAllPermissions(ctx, "edit")
		assert.Error(t, err)
	})

	t.Run("Model_Can", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 'role' AS type`).WillReturnError(sql.ErrConnDone)
		_, err := user.Can(ctx, "edit", "web")
		assert.Error(t, err)
	})

	role := gate.Role("admin", "web")

	t.Run("Role_GivePermissionTo_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnError(sql.ErrConnDone)
		err := role.GivePermissionTo(ctx, "edit")
		assert.Error(t, err)

		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnError(sql.ErrConnDone)
		err = role.GivePermissionTo(ctx, "edit")
		assert.Error(t, err)

		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectExec(`INSERT INTO role_has_permissions`).WillReturnError(sql.ErrConnDone)
		err = role.GivePermissionTo(ctx, "edit")
		assert.Error(t, err)
	})

	t.Run("Role_RevokePermissionTo_DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnError(sql.ErrConnDone)
		err := role.RevokePermissionTo(ctx, "edit")
		assert.Error(t, err)

		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnError(sql.ErrConnDone)
		err = role.RevokePermissionTo(ctx, "edit")
		assert.Error(t, err)

		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectExec(`DELETE FROM role_has_permissions`).WillReturnError(sql.ErrConnDone)
		err = role.RevokePermissionTo(ctx, "edit")
		assert.Error(t, err)
	})

	t.Run("GetRoleNames_RowScanError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.name FROM model_has_roles`).
			WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin").RowError(0, sql.ErrConnDone))
		_, err := user.GetRoleNames(ctx)
		assert.Error(t, err)
	})

	t.Run("GetRolesMap_RowScanError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT r.guard_name, r.name FROM model_has_roles`).
			WillReturnRows(sqlmock.NewRows([]string{"name", "guard_name"}).AddRow("admin", "web").RowError(0, sql.ErrConnDone))
		_, err := user.GetRolesMap(ctx)
		assert.Error(t, err)
	})

	t.Run("GetDirectPermissions_RowScanError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT p.name FROM model_has_permissions`).
			WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("edit").RowError(0, sql.ErrConnDone))
		_, err := user.GetDirectPermissions(ctx)
		assert.Error(t, err)
	})
}
