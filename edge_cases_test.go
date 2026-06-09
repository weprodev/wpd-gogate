package gogate

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestEdgeCases(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	gate := NewGate(db, nil)
	ctx := context.Background()

	t.Run("IsNilOrEmpty", func(t *testing.T) {
		assert.True(t, IsNilOrEmpty(nil))
		assert.True(t, IsNilOrEmpty(""))
		assert.False(t, IsNilOrEmpty("not empty"))
		
		var strPtr *string
		assert.True(t, IsNilOrEmpty(strPtr))

		str := "val"
		assert.False(t, IsNilOrEmpty(&str))

		var emptyUUID [16]byte
		assert.True(t, IsNilOrEmpty(emptyUUID))
		
		validUUID := [16]byte{1}
		assert.False(t, IsNilOrEmpty(validUUID))
		
		assert.False(t, IsNilOrEmpty(123)) // integer is not checked for empty in the func, so it defaults to false
	})

	user := gate.Model("users", "1", nil)

	t.Run("RemoveRole_ErrNoRows", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnError(sql.ErrNoRows)
		err := user.RemoveRole(ctx, "nonexistent", "web")
		assert.NoError(t, err) // Should ignore ErrNoRows
	})

	t.Run("RevokePermissionTo_ErrNoRows", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnError(sql.ErrNoRows)
		err := user.RevokePermissionTo(ctx, "nonexistent", "web")
		assert.NoError(t, err) // Should ignore ErrNoRows
	})

	role := gate.Role("admin", "web")

	t.Run("Role_RevokePermissionTo_ErrNoRows", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnError(sql.ErrNoRows)
		err := role.RevokePermissionTo(ctx, "nonexistent")
		assert.NoError(t, err) // Should ignore ErrNoRows
	})
	
	t.Run("Role_RevokePermissionTo_RoleErrNoRows", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnError(sql.ErrNoRows)
		err := role.RevokePermissionTo(ctx, "nonexistent")
		assert.NoError(t, err) // Should ignore ErrNoRows
	})

	t.Run("Role_GivePermissionTo_ErrNoRows", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnError(sql.ErrNoRows)
		err := role.GivePermissionTo(ctx, "nonexistent")
		assert.Error(t, err)

		mock.ExpectQuery(`SELECT id FROM roles`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectQuery(`SELECT id FROM permissions`).WillReturnError(sql.ErrNoRows)
		err = role.GivePermissionTo(ctx, "nonexistent")
		assert.Error(t, err)
	})

	t.Run("HasAnyRole_Empty", func(t *testing.T) {
		ok, err := user.HasAnyRole(ctx, "web")
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("HasAllRoles_Empty", func(t *testing.T) {
		ok, err := user.HasAllRoles(ctx, "web")
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("HasAnyPermission_Empty", func(t *testing.T) {
		ok, err := user.HasAnyPermission(ctx)
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("HasAllPermissions_Empty", func(t *testing.T) {
		ok, err := user.HasAllPermissions(ctx)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("Role_GetPermissionNames", func(t *testing.T) {
		// Mock memory state
		gate.mu.Lock()
		gate.rolePermissions = map[string]map[string]bool{
			"web:admin": {
				"edit": true,
				"delete": true,
			},
		}
		gate.mu.Unlock()

		perms, err := role.GetPermissionNames(ctx)
		assert.NoError(t, err)
		assert.Contains(t, perms, "edit")
		assert.Contains(t, perms, "delete")
		assert.Len(t, perms, 2)
	})
}
