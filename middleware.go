package gogate

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

// MiddlewareOptions configures how the RBAC middleware behaves.
type MiddlewareOptions struct {
	// ModelType specifies the type of model being checked (default: "users").
	ModelType string
	// ExtractModelID extracts the model identifier (e.g., user UUID) from the context.
	ExtractModelID func(c echo.Context) (any, error)
	// ExtractTeamID extracts the team or workspace identifier (optional, e.g., workspace UUID) from the context.
	ExtractTeamID func(c echo.Context) (any, error)
	// OnDenied defines the response when permission is denied.
	OnDenied func(c echo.Context, permissionName string) error
	// OnError defines the response when an internal database error occurs.
	OnError func(c echo.Context, err error) error
}

// DefaultMiddlewareOptions provides sensible defaults for Echo web applications.
func DefaultMiddlewareOptions() MiddlewareOptions {
	return MiddlewareOptions{
		ModelType: "users",
		ExtractModelID: func(c echo.Context) (any, error) {
			// Check standard http request context value
			if uidVal := c.Request().Context().Value("portal_user_id"); uidVal != nil {
				if uid, ok := uidVal.(string); ok && uid != "" {
					return uid, nil
				}
			}
			// Check echo context value
			if uid, ok := c.Get("userID").(string); ok && uid != "" {
				return uid, nil
			}
			return nil, errors.New("user identifier not found in context")
		},
		ExtractTeamID: func(c echo.Context) (any, error) {
			// Extract from Echo path param ":wid"
			if wid := c.Param("wid"); wid != "" {
				return wid, nil
			}
			return nil, nil // optional team ID
		},
		OnDenied: func(c echo.Context, permissionName string) error {
			return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("Forbidden: missing permission %q", permissionName))
		},
		OnError: func(c echo.Context, err error) error {
			return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error: authorization check failed")
		},
	}
}

// RequirePermission returns an Echo middleware enforcing that the authenticated model has the required permission.
func RequirePermission(gate *Gate, permissionName string, opts *MiddlewareOptions) echo.MiddlewareFunc {
	var options MiddlewareOptions
	if opts != nil {
		options = *opts
	} else {
		options = DefaultMiddlewareOptions()
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Extract model ID
			modelID, err := options.ExtractModelID(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized: " + err.Error())
			}

			// Extract team ID (optional)
			teamID, err := options.ExtractTeamID(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Bad Request: " + err.Error())
			}

			// Verify permission using the Gate
			allowed, err := gate.Check(c.Request().Context(), options.ModelType, modelID, permissionName, teamID)
			if err != nil {
				return options.OnError(c, err)
			}

			if !allowed {
				return options.OnDenied(c, permissionName)
			}

			return next(c)
		}
	}
}
