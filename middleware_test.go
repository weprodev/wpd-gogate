package gogate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware_DefaultMiddlewareOptions(t *testing.T) {
	opts := DefaultMiddlewareOptions()
	assert.Equal(t, "users", opts.ModelType)
	assert.NotNil(t, opts.ExtractModelID)
	assert.NotNil(t, opts.ExtractTeamID)
	assert.NotNil(t, opts.OnDenied)
	assert.NotNil(t, opts.OnError)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Test ExtractModelID missing
	_, err := opts.ExtractModelID(c)
	assert.Error(t, err)

	// Test ExtractModelID from portal_user_id ctx
	type contextKey string
	ctx := context.WithValue(req.Context(), contextKey("portal_user_id"), "ctx_user")
	req2 := req.WithContext(ctx)
	c2 := e.NewContext(req2, rec)
	id, err := opts.ExtractModelID(c2)
	assert.NoError(t, err)
	assert.Equal(t, "ctx_user", id)

	// Test ExtractModelID from echo context
	c.Set("userID", "echo_user")
	id, err = opts.ExtractModelID(c)
	assert.NoError(t, err)
	assert.Equal(t, "echo_user", id)

	// Test ExtractTeamID missing
	tid, err := opts.ExtractTeamID(c)
	assert.NoError(t, err)
	assert.Nil(t, tid)

	// Test ExtractTeamID from param
	c.SetParamNames("wid")
	c.SetParamValues("team1")
	tid, err = opts.ExtractTeamID(c)
	assert.NoError(t, err)
	assert.Equal(t, "team1", tid)

	// Test OnDenied
	err = opts.OnDenied(c, "edit")
	assert.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusForbidden, he.Code)

	// Test OnError
	err = opts.OnError(c, errors.New("db error"))
	assert.Error(t, err)
	he, ok = err.(*echo.HTTPError)
	assert.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, he.Code)
}

func TestMiddleware_RequirePermission(t *testing.T) {
	e := echo.New()

	t.Run("MissingModelID", func(t *testing.T) {
		db, _, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close() //nolint:errcheck
		gate := NewGate(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := RequirePermission(gate, "edit_post", nil)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err = handler(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, he.Code)
	})

	t.Run("ExtractTeamIDError", func(t *testing.T) {
		db, _, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close() //nolint:errcheck
		gate := NewGate(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("userID", "user1")

		opts := DefaultMiddlewareOptions()
		opts.ExtractTeamID = func(c echo.Context) (any, error) {
			return nil, errors.New("team id extraction failed")
		}

		handler := RequirePermission(gate, "edit_post", &opts)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err = handler(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, he.Code)
	})

	t.Run("CheckError", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close() //nolint:errcheck
		gate := NewGate(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("userID", "user1")

		mock.ExpectQuery(`SELECT 'role' AS type`).
			WithArgs("users", "user1", "web", "edit_post").
			WillReturnError(errors.New("db error"))

		handler := RequirePermission(gate, "edit_post", nil)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err = handler(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusInternalServerError, he.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("AccessDenied", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close() //nolint:errcheck
		gate := NewGate(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("userID", "user1")

		mock.ExpectQuery(`SELECT 'role' AS type`).
			WithArgs("users", "user1", "web", "edit_post").
			WillReturnRows(sqlmock.NewRows([]string{"type", "value"}))

		handler := RequirePermission(gate, "edit_post", nil)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err = handler(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, he.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("AccessGranted", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close() //nolint:errcheck
		gate := NewGate(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("userID", "user1")

		mock.ExpectQuery(`SELECT 'role' AS type`).
			WithArgs("users", "user1", "web", "edit_post").
			WillReturnRows(sqlmock.NewRows([]string{"type", "value"}).AddRow("permission", "edit_post"))

		handler := RequirePermission(gate, "edit_post", nil)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err = handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("CustomOptions", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close() //nolint:errcheck
		gate := NewGate(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		opts := DefaultMiddlewareOptions()
		opts.ExtractModelID = func(c echo.Context) (any, error) { return "custom_user", nil }
		opts.ExtractTeamID = func(c echo.Context) (any, error) { return "custom_team", nil }
		opts.GuardName = "api"

		mock.ExpectQuery(`SELECT 'role' AS type`).
			WithArgs("users", "custom_user", "api", "edit_post", "custom_team").
			WillReturnRows(sqlmock.NewRows([]string{"type", "value"}).AddRow("permission", "edit_post"))

		handler := RequirePermission(gate, "edit_post", &opts)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err = handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
