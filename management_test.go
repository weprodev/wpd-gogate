package gogate

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestGate_CreateRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO roles \(name, guard_name\)`).
			WithArgs("admin", "web").
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := gate.CreateRole(ctx, "admin", "web")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("AlreadyExists", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO roles \(name, guard_name\)`).
			WithArgs("admin", "web").
			WillReturnResult(sqlmock.NewResult(1, 0)) // 0 rows affected

		err := gate.CreateRole(ctx, "admin", "web")
		assert.ErrorIs(t, err, ErrRoleAlreadyExists)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DBError", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO roles \(name, guard_name\)`).
			WithArgs("admin", "web").
			WillReturnError(sql.ErrConnDone)

		err := gate.CreateRole(ctx, "admin", "web")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wpd-gogate: create role")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGate_CreatePermission(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO permissions \(name, guard_name\)`).
			WithArgs("edit", "web").
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := gate.CreatePermission(ctx, "edit", "web")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("AlreadyExists", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO permissions \(name, guard_name\)`).
			WithArgs("edit", "web").
			WillReturnResult(sqlmock.NewResult(1, 0)) // 0 rows affected

		err := gate.CreatePermission(ctx, "edit", "web")
		assert.ErrorIs(t, err, ErrPermissionAlreadyExists)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DBError", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO permissions \(name, guard_name\)`).
			WithArgs("edit", "web").
			WillReturnError(sql.ErrConnDone)

		err := gate.CreatePermission(ctx, "edit", "web")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wpd-gogate: create permission")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGate_DeleteRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec(`DELETE FROM roles`).
			WithArgs("admin").
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := gate.DeleteRole(ctx, "admin")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DBError", func(t *testing.T) {
		mock.ExpectExec(`DELETE FROM roles`).
			WithArgs("admin").
			WillReturnError(sql.ErrConnDone)

		err := gate.DeleteRole(ctx, "admin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wpd-gogate: delete role")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGate_DeletePermission(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec(`DELETE FROM permissions`).
			WithArgs("edit").
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := gate.DeletePermission(ctx, "edit")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DBError", func(t *testing.T) {
		mock.ExpectExec(`DELETE FROM permissions`).
			WithArgs("edit").
			WillReturnError(sql.ErrConnDone)

		err := gate.DeletePermission(ctx, "edit")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wpd-gogate: delete permission")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGate_GetAllRolesMap(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"guard_name", "name"}).
			AddRow("web", "admin").
			AddRow("web", "user").
			AddRow("api", "admin")

		mock.ExpectQuery(`SELECT guard_name, name FROM roles`).
			WillReturnRows(rows)

		result, err := gate.GetAllRolesMap(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, []string{"admin", "user"}, result["web"])
		assert.Equal(t, []string{"admin"}, result["api"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT guard_name, name FROM roles`).
			WillReturnError(sql.ErrConnDone)

		result, err := gate.GetAllRolesMap(ctx)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "wpd-gogate: get all roles")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("RowScanError", func(t *testing.T) {
		// Mock rows with wrong type to trigger scan error. sqlmock's RowError is better.
		rows := sqlmock.NewRows([]string{"guard_name", "name"}).
			AddRow("web", "admin").
			RowError(0, sql.ErrConnDone)

		mock.ExpectQuery(`SELECT guard_name, name FROM roles`).
			WillReturnRows(rows)

		result, err := gate.GetAllRolesMap(ctx)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "wpd-gogate: read role rows")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGate_GetAllPermissionsMap(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close() //nolint:errcheck

	gate := NewGate(db, nil)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"guard_name", "name"}).
			AddRow("web", "create").
			AddRow("web", "edit").
			AddRow("api", "delete")

		mock.ExpectQuery(`SELECT guard_name, name FROM permissions`).
			WillReturnRows(rows)

		result, err := gate.GetAllPermissionsMap(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, []string{"create", "edit"}, result["web"])
		assert.Equal(t, []string{"delete"}, result["api"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DBError", func(t *testing.T) {
		mock.ExpectQuery(`SELECT guard_name, name FROM permissions`).
			WillReturnError(sql.ErrConnDone)

		result, err := gate.GetAllPermissionsMap(ctx)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "wpd-gogate: get all permissions")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("RowScanError", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"guard_name", "name"}).
			AddRow("web", "create").
			RowError(0, sql.ErrConnDone)

		mock.ExpectQuery(`SELECT guard_name, name FROM permissions`).
			WillReturnRows(rows)

		result, err := gate.GetAllPermissionsMap(ctx)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "wpd-gogate: read permission rows")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
