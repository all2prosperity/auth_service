package rbac

import (
	"context"
	"fmt"
	"strings"
)

// Role represents a user role
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleSecOps  Role = "secops"
	RoleSupport Role = "support"
)

// Permission represents a permission action
type Permission string

const (
	// User management permissions
	PermissionUserView       Permission = "user:view"
	PermissionUserLock       Permission = "user:lock"
	PermissionUserUnlock     Permission = "user:unlock"
	PermissionUserRoleUpdate Permission = "user:role_update"
	PermissionTokenRevoke    Permission = "token:revoke"

	// Audit permissions
	PermissionAuditView Permission = "audit:view"

	// Statistics permissions
	PermissionStatsView Permission = "stats:view"

	// Settings permissions
	PermissionSettingsView   Permission = "settings:view"
	PermissionSettingsUpdate Permission = "settings:update"
)

// RolePermissions defines permissions for each role
var RolePermissions = map[Role][]Permission{
	RoleAdmin: {
		// Admin has all permissions
		PermissionUserView,
		PermissionUserLock,
		PermissionUserUnlock,
		PermissionUserRoleUpdate,
		PermissionTokenRevoke,
		PermissionAuditView,
		PermissionStatsView,
		PermissionSettingsView,
		PermissionSettingsUpdate,
	},
	RoleSecOps: {
		// Security operations: can manage users and view audit/stats
		PermissionUserView,
		PermissionUserLock,
		PermissionUserUnlock,
		PermissionTokenRevoke,
		PermissionAuditView,
		PermissionStatsView,
		PermissionSettingsView,
	},
	RoleSupport: {
		// Support: can only view users and basic stats
		PermissionUserView,
		PermissionStatsView,
	},
}

// Guard handles role-based access control
type Guard struct{}

// NewGuard creates a new RBAC guard
func NewGuard() *Guard {
	return &Guard{}
}

// UserContext represents user context for authorization
type UserContext struct {
	UserID string   `json:"user_id"`
	Roles  []string `json:"roles"`
	Email  string   `json:"email"`
}

// HasRole checks if the user has the specified role
func (uc *UserContext) HasRole(role Role) bool {
	for _, r := range uc.Roles {
		if Role(r) == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the user has any of the specified roles
func (uc *UserContext) HasAnyRole(roles ...Role) bool {
	for _, role := range roles {
		if uc.HasRole(role) {
			return true
		}
	}
	return false
}

// GetHighestRole returns the highest privilege role
func (uc *UserContext) GetHighestRole() Role {
	if uc.HasRole(RoleAdmin) {
		return RoleAdmin
	}
	if uc.HasRole(RoleSecOps) {
		return RoleSecOps
	}
	if uc.HasRole(RoleSupport) {
		return RoleSupport
	}
	return ""
}

// CheckPermission checks if the user has the specified permission
func (g *Guard) CheckPermission(ctx context.Context, userCtx *UserContext, permission Permission) error {
	if userCtx == nil {
		return fmt.Errorf("user context is required")
	}

	// Check each role's permissions
	for _, roleStr := range userCtx.Roles {
		role := Role(roleStr)
		if permissions, exists := RolePermissions[role]; exists {
			for _, perm := range permissions {
				if perm == permission {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("insufficient permissions: user %s lacks permission %s", userCtx.UserID, permission)
}

// RequireAnyRole middleware function that requires any of the specified roles
func (g *Guard) RequireAnyRole(roles ...Role) func(*UserContext) error {
	return func(userCtx *UserContext) error {
		if userCtx == nil {
			return fmt.Errorf("authentication required")
		}

		if !userCtx.HasAnyRole(roles...) {
			roleStrs := make([]string, len(roles))
			for i, role := range roles {
				roleStrs[i] = string(role)
			}
			return fmt.Errorf("insufficient permissions: requires one of roles [%s]", strings.Join(roleStrs, ", "))
		}

		return nil
	}
}

// RequirePermission checks if the user has the required permission
func (g *Guard) RequirePermission(permission Permission) func(*UserContext) error {
	return func(userCtx *UserContext) error {
		return g.CheckPermission(context.Background(), userCtx, permission)
	}
}

// CanManageUser checks if the user can manage another user
func (g *Guard) CanManageUser(adminCtx *UserContext, targetUserRole string) bool {
	if adminCtx == nil {
		return false
	}

	adminRole := adminCtx.GetHighestRole()

	// Admin can manage everyone except other admins (unless same user)
	if adminRole == RoleAdmin {
		return true
	}

	// SecOps can manage support and regular users
	if adminRole == RoleSecOps {
		return targetUserRole != string(RoleAdmin)
	}

	// Support cannot manage anyone
	return false
}

// GetAllowedRoles returns roles that the current user can assign to others
func (g *Guard) GetAllowedRoles(userCtx *UserContext) []Role {
	if userCtx == nil {
		return []Role{}
	}

	role := userCtx.GetHighestRole()

	switch role {
	case RoleAdmin:
		// Admin can assign any role except admin (for security)
		return []Role{RoleSecOps, RoleSupport}
	case RoleSecOps:
		// SecOps can only assign support role
		return []Role{RoleSupport}
	default:
		// Other roles cannot assign roles
		return []Role{}
	}
}

// IsValidRole checks if the role is valid
func IsValidRole(role string) bool {
	switch Role(role) {
	case RoleAdmin, RoleSecOps, RoleSupport:
		return true
	default:
		return false
	}
}
