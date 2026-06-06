# wpd-gogate

A clean, idiomatic, and high-performance Go Role-Based Access Control (RBAC) library.

`wpd-gogate` is fully framework-agnostic, database-agnostic, supports multi-tenant team/workspace scoping, polymorphic model checking, and leverages a high-speed in-memory cache to achieve sub-microsecond authorization decisions.

---

## Features

- **Sub-microsecond Evaluations**: Role-permission matrices are cached in a thread-safe synchronized map on startup. Check times are measured in nanoseconds.
- **Relational Schema**: Utilizes a highly flexible, polymorphic 5-table relational database schema.
- **Polymorphic Targets**: Query and assign permissions on any target entity (e.g. `users`, `api_keys`, `services`) using `model_type` and `model_id`.
- **Scoped Scenarios (Teams/Workspaces)**: Assign roles and permissions scoped to specific workspaces, groups, or teams using an optional `team_id`.
- **Fluent Chaining API**: Ergonomic Go API:
  ```go
  user := gate.Model("users", userID, teamID)
  user.AssignRole(ctx, "writer")
  user.Can(ctx, "edit articles")
  ```
- **Zero-DB Checked Fast Path**: Perform pure in-memory checks (`gate.HasRolePermission("admin", "edit articles")`) if the user's role has already been resolved in context or JWT.
- **Instant Cache Updates**: Modifying a role's permissions or deleting a role instantly updates the in-memory cache, keeping clustered nodes consistent without complex event listeners.
- **Echo Framework Integration**: Built-in routing middleware for fast integration into your Echo handler stack.

---

## Installation

```bash
go get github.com/weprodev/wpd-gogate
```

---

## Database Schema

`wpd-gogate` manages roles and permissions using a standard relational structure. Instead of storing access checks in code or custom config files, everything is managed securely in your PostgreSQL database.

The package utilizes 5 tables:
1. `permissions`: Stores permission names (e.g., `users.list`, `articles.create`).
2. `roles`: Stores role names (e.g., `admin`, `editor`).
3. `role_has_permissions`: Links permissions to roles (which roles can perform which actions).
4. `model_has_roles`: Assigns roles to models (e.g., assigning the `editor` role to a specific user within a specific workspace/team).
5. `model_has_permissions`: Assigns direct permission overrides to models (e.g., giving a specific user `articles.delete` even if their role doesn't allow it).

### Understanding `guard_name`

The `guard_name` column defines the **authentication boundary** or **context** under which a role or permission is valid.

#### 1. Scoping Multiple Authentication Systems
In complex systems, you often have different ways of authenticating users, each having its own context. For example:
- **`web`**: Standard human portal users authenticated via JWT or session cookies.
- **`api`**: External API clients or services authenticated via API keys or client credentials.
- **`admin`**: Internal super-admins logging into an employee-only panel.

By defining `guard_name`, you prevent permissions from leaking across different interfaces. A user might have the `settings.write` permission under the `web` guard, but an API key might require the `settings.write` permission under the `api` guard.

#### 2. Preventing Name Collisions
The database enforces a unique constraint on permission/role names per guard:
```sql
CONSTRAINT permissions_name_guard_unique UNIQUE (name, guard_name)
```
This allows you to define identical permission names (e.g., `logs.read`) under different guards without collision, keeping their mappings fully isolated.

#### 3. Default Value
By default, the library sets `guard_name` to `'web'` if it is not explicitly specified.

### Running Migrations
We provide standard Postgres migration files under the `migrations/` folder. Simply run the UP migration file on your database client or migration manager to create the tables:
- **UP Migration (Creates Tables)**: [migrations/create_permission_tables.up.sql](file:///Users/michael/Sites/WeProDev/wpd-gogate/migrations/create_permission_tables.up.sql)
- **DOWN Migration (Removes Tables)**: [migrations/create_permission_tables.down.sql](file:///Users/michael/Sites/WeProDev/wpd-gogate/migrations/create_permission_tables.down.sql)

---

## Database Seeding

To quickly set up standard roles and associate them with permissions, you can use our pre-configured SQL seeder. This script inserts standard roles (`admin`, `editor`, `writer`, `viewer`), registers basic permissions, and maps them together using dynamic SQL queries.

- **SQL Seeder Script**: [seeds/seed_roles_permissions.sql](file:///Users/michael/Sites/WeProDev/wpd-gogate/seeds/seed_roles_permissions.sql)

To seed your database, run the script against your PostgreSQL instance using `psql` or your preferred SQL tool:

```bash
psql -U your_user -d your_database -f seeds/seed_roles_permissions.sql
```

---

## Quickstart Guide

### 1. Initialize the Gate
Instantiate the `Gate` with your database handle and call `LoadPolicy` on boot to populate the cache:

```go
package main

import (
	"context"
	"database/sql"
	"log"

	"github.com/weprodev/wpd-gogate"
	_ "github.com/lib/pq"
)

func main() {
	db, err := sql.Open("postgres", "host=localhost user=postgres dbname=app sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	// Initialize gate with defaults
	gate := gogate.NewGate(db, nil)

	// Load role-permission relations into memory cache
	ctx := context.Background()
	if err := gate.LoadPolicy(ctx); err != nil {
		log.Fatalf("failed to load policies: %v", err)
	}
}
```

### 2. Configure Roles & Permissions (Admin API)
Programmatically configure your roles, permissions, and mappings:

```go
// Create roles & permissions
_ = gate.CreateRole(ctx, "writer", "web")
_ = gate.CreatePermission(ctx, "edit articles", "web")

// Give permission to a role
_ = gate.Role("writer").GivePermissionTo(ctx, "edit articles")
```

### 3. Assign & Verify Access (Fluent Model API)
Perform authorization checks on polymorphic models:

```go
userID := "00000000-0000-0000-0000-000000000010"
workspaceID := "00000000-0000-0000-0000-000000000001"

// Scoped model reference
user := gate.Model("users", userID, workspaceID)

// Assign role
_ = user.AssignRole(ctx, "writer")

// Check if user has permission (inherits "edit articles" from "writer" role)
hasAccess, err := user.Can(ctx, "edit articles")
if hasAccess {
    // Authorized!
}

// Give a direct permission override (ignores roles)
_ = user.GivePermissionTo(ctx, "publish posts")
```

### 4. Zero-DB Fast Path (In-Memory Check)
If your user's role has already been resolved (e.g. injected into context or parsed from a JWT claim), you can perform a pure memory lookup with no database queries:

```go
if gate.HasRolePermission("admin", "delete posts") {
    // Authorized in nanoseconds!
}
```

---

## Integration Guide (Routes, Middleware, Handlers)

`wpd-gogate` is designed to be highly versatile. Here are the three primary patterns for integrating authorization checks into your Echo application.

### 1. Route-Level Authorization (Declarative Routes)
You can protect individual routes or entire route groups declaratively during route registration. This keeps your handlers focused entirely on business logic.

```go
package main

import (
	"context"
	"database/sql"
	"github.com/labstack/echo/v4"
	"github.com/weprodev/wpd-gogate"
)

func main() {
	db, _ := sql.Open("postgres", "...")
	gate := gogate.NewGate(db, nil)
	_ = gate.LoadPolicy(context.Background())

	e := echo.New()

	// 1. Protecting individual endpoints
	e.GET("/templates", listTemplates, gogate.RequirePermission(gate, "templates.list", nil))

	// 2. Protecting route groups
	adminGroup := e.Group("/admin")
	adminGroup.Use(gogate.RequirePermission(gate, "admin.access", nil))
	adminGroup.POST("/settings", updateSettings)
}
```

### 2. Custom Middleware Configuration (Dynamic Context Scoping)
If your application stores user contexts or workspace scopes differently (e.g., in request headers, custom session variables, or specific path variables), you can configure `MiddlewareOptions` to resolve identifiers dynamically:

```go
// Protect workspace settings with custom ID extraction
opts := gogate.MiddlewareOptions{
    ModelType: "users",
    ExtractModelID: func(c echo.Context) (any, error) {
        // Extract the user UUID from a custom JWT context attribute
        userID, ok := c.Get("authenticated_user_id").(string)
        if !ok || userID == "" {
            return nil, echo.NewHTTPError(http.StatusUnauthorized, "User context missing")
        }
        return userID, nil
    },
    ExtractTeamID: func(c echo.Context) (any, error) {
        // Extract workspace/team UUID from a custom header instead of path parameters
        workspaceID := c.Request().Header.Get("X-Workspace-ID")
        if workspaceID == "" {
            return nil, echo.NewHTTPError(http.StatusBadRequest, "X-Workspace-ID header required")
        }
        return workspaceID, nil
    },
    OnDenied: func(c echo.Context, permissionName string) error {
        return c.JSON(http.StatusForbidden, map[string]string{
            "error":      "Access Denied",
            "permission": permissionName,
        })
    },
}

// Attach the configured middleware
e.GET("/settings", getSettings, gogate.RequirePermission(gate, "settings.read", &opts))
```

### 3. Imperative Authorization in Handlers (Controller Logic)
For complex scenarios where authorization depends on entity ownership or path attributes loaded dynamically inside the controller, you can use the fluent API directly inside your handlers:

```go
func DeleteArticle(c echo.Context) error {
	ctx := c.Request().Context()
	userID := c.Get("userID").(string)
	workspaceID := c.Param("wid")
	articleID := c.Param("articleId")

	// 1. Resolve fluent ModelRef for the active user & workspace
	user := gate.Model("users", userID, workspaceID)

	// 2. Perform permission check
	hasAdminAccess, err := user.Can(ctx, "articles.delete")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Auth service error")
	}

	// 3. Fallback check: check if the user is the owner of the article
	isOwner := checkIfUserOwnsArticle(articleID, userID)

	if !hasAdminAccess && !isOwner {
		return echo.NewHTTPError(http.StatusForbidden, "You do not have permission to delete this article")
	}

	// Proceed with deletion logic...
	return c.NoContent(http.StatusNoContent)
}
```

---

## Local Development & Testing

We provide a self-contained local development script and a Docker compose file to run integration tests against a real Postgres database.

### Running Audit (Fmt + Lint + Race tests)
```bash
make audit
```

### Database Integration Testing
```bash
# Starts Postgres container, runs tests with Postgres connection, stops container
make test-integration
```
