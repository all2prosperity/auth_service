package service

import (
	"context"
	"fmt"
	"time"

	"auth_service/internal/console/audit"
	"auth_service/internal/console/metrics"
	"auth_service/internal/console/rbac"
	"auth_service/internal/console/store"

	"golang.org/x/time/rate"
)

// ConsoleService handles business logic for console operations
type ConsoleService struct {
	store       store.Store
	rbacGuard   *rbac.Guard
	metrics     *metrics.Metrics
	rateLimiter *rate.Limiter
}

// NewConsoleService creates a new console service
func NewConsoleService(
	store store.Store,
	rbacGuard *rbac.Guard,
	metrics *metrics.Metrics,
) *ConsoleService {
	// Rate limiter: 10 requests per minute for mutations
	limiter := rate.NewLimiter(rate.Every(6*time.Second), 10)

	return &ConsoleService{
		store:       store,
		rbacGuard:   rbacGuard,
		metrics:     metrics,
		rateLimiter: limiter,
	}
}

// ListUsersRequest represents the request for listing users
type ListUsersRequest struct {
	AdminContext *rbac.UserContext
	Page         int
	PageSize     int
	Search       string
	Status       string
	Role         string
	IPAddress    string
}

// ListUsers retrieves users with permission checks
func (s *ConsoleService) ListUsers(ctx context.Context, req ListUsersRequest) (*store.ListUsersResponse, error) {
	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionUserView); err != nil {
		s.metrics.RecordError("list_users", "permission_denied")
		return nil, fmt.Errorf("permission denied: %w", err)
	}

	// Convert status string to enum
	var status store.UserStatus
	if req.Status != "" {
		status = store.UserStatusFromString(req.Status)
	}

	// Create store request
	storeReq := store.ListUsersRequest{
		Page:     req.Page,
		PageSize: req.PageSize,
		Search:   req.Search,
		Status:   status,
		Role:     req.Role,
	}

	// Execute query
	response, err := s.store.ListUsers(ctx, storeReq)
	if err != nil {
		s.metrics.RecordError("list_users", "store_error")
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Log audit event
	s.store.CreateAuditLog(ctx, audit.LogRequest{
		AdminID:   req.AdminContext.UserID,
		Action:    audit.ActionUserViewed,
		Details:   map[string]interface{}{"search": req.Search, "count": len(response.Users)},
		IPAddress: req.IPAddress,
	})

	s.metrics.RecordRequest("GET", "/users", "200")
	return response, nil
}

// GetUserRequest represents the request for getting a user
type GetUserRequest struct {
	AdminContext *rbac.UserContext
	UserID       string
	IPAddress    string
}

// GetUser retrieves a single user with permission checks
func (s *ConsoleService) GetUser(ctx context.Context, req GetUserRequest) (*store.UserInfo, error) {
	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionUserView); err != nil {
		s.metrics.RecordError("get_user", "permission_denied")
		return nil, fmt.Errorf("permission denied: %w", err)
	}

	// Get user
	user, err := s.store.GetUser(ctx, req.UserID)
	if err != nil {
		s.metrics.RecordError("get_user", "store_error")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Log audit event
	s.store.CreateAuditLog(ctx, audit.LogRequest{
		AdminID:   req.AdminContext.UserID,
		Action:    audit.ActionUserViewed,
		TargetID:  req.UserID,
		IPAddress: req.IPAddress,
	})

	s.metrics.RecordRequest("GET", "/users/{id}", "200")
	return user, nil
}

// LockUserRequest represents the request for locking a user
type LockUserRequest struct {
	AdminContext *rbac.UserContext
	UserID       string
	Reason       string
	IPAddress    string
}

// LockUser locks a user account with permission and rate limiting checks
func (s *ConsoleService) LockUser(ctx context.Context, req LockUserRequest) error {
	// Check rate limit
	if !s.rateLimiter.Allow() {
		s.metrics.RecordError("lock_user", "rate_limit_exceeded")
		return fmt.Errorf("rate limit exceeded")
	}

	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionUserLock); err != nil {
		s.metrics.RecordError("lock_user", "permission_denied")
		return fmt.Errorf("permission denied: %w", err)
	}

	// Get target user to check if admin can manage them
	targetUser, err := s.store.GetUser(ctx, req.UserID)
	if err != nil {
		s.metrics.RecordError("lock_user", "user_not_found")
		return fmt.Errorf("user not found: %w", err)
	}

	// Check if admin can manage this user
	if !s.rbacGuard.CanManageUser(req.AdminContext, targetUser.Role) {
		s.metrics.RecordError("lock_user", "insufficient_privileges")
		return fmt.Errorf("insufficient privileges to manage user with role: %s", targetUser.Role)
	}

	// Lock user
	if err := s.store.LockUser(ctx, req.UserID, req.Reason); err != nil {
		s.metrics.RecordError("lock_user", "store_error")
		return fmt.Errorf("failed to lock user: %w", err)
	}

	// Log audit event
	s.store.CreateAuditLog(ctx, audit.LogRequest{
		AdminID:   req.AdminContext.UserID,
		Action:    audit.ActionUserLocked,
		TargetID:  req.UserID,
		Details:   map[string]interface{}{"reason": req.Reason},
		IPAddress: req.IPAddress,
	})

	s.metrics.RecordUserLock(req.AdminContext.UserID, req.Reason)
	s.metrics.RecordRequest("POST", "/users/{id}/lock", "200")
	return nil
}

// UnlockUserRequest represents the request for unlocking a user
type UnlockUserRequest struct {
	AdminContext *rbac.UserContext
	UserID       string
	Reason       string
	IPAddress    string
}

// UnlockUser unlocks a user account with permission and rate limiting checks
func (s *ConsoleService) UnlockUser(ctx context.Context, req UnlockUserRequest) error {
	// Check rate limit
	if !s.rateLimiter.Allow() {
		s.metrics.RecordError("unlock_user", "rate_limit_exceeded")
		return fmt.Errorf("rate limit exceeded")
	}

	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionUserUnlock); err != nil {
		s.metrics.RecordError("unlock_user", "permission_denied")
		return fmt.Errorf("permission denied: %w", err)
	}

	// Get target user to check if admin can manage them
	targetUser, err := s.store.GetUser(ctx, req.UserID)
	if err != nil {
		s.metrics.RecordError("unlock_user", "user_not_found")
		return fmt.Errorf("user not found: %w", err)
	}

	// Check if admin can manage this user
	if !s.rbacGuard.CanManageUser(req.AdminContext, targetUser.Role) {
		s.metrics.RecordError("unlock_user", "insufficient_privileges")
		return fmt.Errorf("insufficient privileges to manage user with role: %s", targetUser.Role)
	}

	// Unlock user
	if err := s.store.UnlockUser(ctx, req.UserID); err != nil {
		s.metrics.RecordError("unlock_user", "store_error")
		return fmt.Errorf("failed to unlock user: %w", err)
	}

	// Log audit event
	s.store.CreateAuditLog(ctx, audit.LogRequest{
		AdminID:   req.AdminContext.UserID,
		Action:    audit.ActionUserUnlocked,
		TargetID:  req.UserID,
		Details:   map[string]interface{}{"reason": req.Reason},
		IPAddress: req.IPAddress,
	})

	s.metrics.RecordUserUnlock(req.AdminContext.UserID, req.Reason)
	s.metrics.RecordRequest("POST", "/users/{id}/unlock", "200")
	return nil
}

// UpdateUserRoleRequest represents the request for updating user role
type UpdateUserRoleRequest struct {
	AdminContext *rbac.UserContext
	UserID       string
	NewRole      string
	IPAddress    string
}

// UpdateUserRole updates a user's role with permission checks
func (s *ConsoleService) UpdateUserRole(ctx context.Context, req UpdateUserRoleRequest) error {
	// Check rate limit
	if !s.rateLimiter.Allow() {
		s.metrics.RecordError("update_user_role", "rate_limit_exceeded")
		return fmt.Errorf("rate limit exceeded")
	}

	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionUserRoleUpdate); err != nil {
		s.metrics.RecordError("update_user_role", "permission_denied")
		return fmt.Errorf("permission denied: %w", err)
	}

	// Validate role
	if !rbac.IsValidRole(req.NewRole) {
		s.metrics.RecordError("update_user_role", "invalid_role")
		return fmt.Errorf("invalid role: %s", req.NewRole)
	}

	// Check if admin can assign this role
	allowedRoles := s.rbacGuard.GetAllowedRoles(req.AdminContext)
	canAssign := false
	for _, allowedRole := range allowedRoles {
		if string(allowedRole) == req.NewRole {
			canAssign = true
			break
		}
	}
	if !canAssign {
		s.metrics.RecordError("update_user_role", "role_assignment_not_allowed")
		return fmt.Errorf("not allowed to assign role: %s", req.NewRole)
	}

	// Get current user info
	currentUser, err := s.store.GetUser(ctx, req.UserID)
	if err != nil {
		s.metrics.RecordError("update_user_role", "user_not_found")
		return fmt.Errorf("user not found: %w", err)
	}

	// Update role
	if err := s.store.UpdateUserRole(ctx, req.UserID, req.NewRole); err != nil {
		s.metrics.RecordError("update_user_role", "store_error")
		return fmt.Errorf("failed to update user role: %w", err)
	}

	// Log audit event
	s.store.CreateAuditLog(ctx, audit.LogRequest{
		AdminID:  req.AdminContext.UserID,
		Action:   audit.ActionUserRoleUpdate,
		TargetID: req.UserID,
		Details: map[string]interface{}{
			"old_role": currentUser.Role,
			"new_role": req.NewRole,
		},
		IPAddress: req.IPAddress,
	})

	s.metrics.RecordRoleUpdate(req.AdminContext.UserID, currentUser.Role, req.NewRole)
	s.metrics.RecordRequest("PUT", "/users/{id}/role", "200")
	return nil
}

// RevokeUserTokensRequest represents the request for revoking user tokens
type RevokeUserTokensRequest struct {
	AdminContext *rbac.UserContext
	UserID       string
	Reason       string
	IPAddress    string
}

// RevokeUserTokens revokes all tokens for a user
func (s *ConsoleService) RevokeUserTokens(ctx context.Context, req RevokeUserTokensRequest) (int, error) {
	// Check rate limit
	if !s.rateLimiter.Allow() {
		s.metrics.RecordError("revoke_tokens", "rate_limit_exceeded")
		return 0, fmt.Errorf("rate limit exceeded")
	}

	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionTokenRevoke); err != nil {
		s.metrics.RecordError("revoke_tokens", "permission_denied")
		return 0, fmt.Errorf("permission denied: %w", err)
	}

	// Revoke tokens
	count, err := s.store.RevokeUserTokens(ctx, req.UserID)
	if err != nil {
		s.metrics.RecordError("revoke_tokens", "store_error")
		return 0, fmt.Errorf("failed to revoke tokens: %w", err)
	}

	// Log audit event
	s.store.CreateAuditLog(ctx, audit.LogRequest{
		AdminID:  req.AdminContext.UserID,
		Action:   audit.ActionTokensRevoked,
		TargetID: req.UserID,
		Details: map[string]interface{}{
			"reason":        req.Reason,
			"revoked_count": count,
		},
		IPAddress: req.IPAddress,
	})

	s.metrics.RecordTokenRevocation(req.AdminContext.UserID, req.Reason)
	s.metrics.RecordRequest("POST", "/users/{id}/revoke-tokens", "200")
	return count, nil
}

// GetAuditLogsRequest represents the request for getting audit logs
type GetAuditLogsRequest struct {
	AdminContext *rbac.UserContext
	Page         int
	PageSize     int
	UserID       string
	Action       string
	StartTime    time.Time
	EndTime      time.Time
	IPAddress    string
}

// GetAuditLogs retrieves audit logs with permission checks
func (s *ConsoleService) GetAuditLogs(ctx context.Context, req GetAuditLogsRequest) (*audit.ListResponse, error) {
	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionAuditView); err != nil {
		s.metrics.RecordError("get_audit_logs", "permission_denied")
		return nil, fmt.Errorf("permission denied: %w", err)
	}

	// Create audit request
	auditReq := audit.ListRequest{
		Page:      req.Page,
		PageSize:  req.PageSize,
		UserID:    req.UserID,
		Action:    req.Action,
		StartTime: req.StartTime,
		EndTime:   req.EndTime,
	}

	// Get audit logs
	response, err := s.store.ListAuditLogs(ctx, auditReq)
	if err != nil {
		s.metrics.RecordError("get_audit_logs", "store_error")
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}

	// Log audit event
	s.store.CreateAuditLog(ctx, audit.LogRequest{
		AdminID:   req.AdminContext.UserID,
		Action:    audit.ActionAuditViewed,
		Details:   map[string]interface{}{"count": len(response.Logs)},
		IPAddress: req.IPAddress,
	})

	s.metrics.RecordAuditQuery(req.AdminContext.UserID)
	s.metrics.RecordRequest("GET", "/audit-logs", "200")
	return response, nil
}

// GetCodeStatsRequest represents the request for getting code statistics
type GetCodeStatsRequest struct {
	AdminContext *rbac.UserContext
	StartTime    time.Time
	EndTime      time.Time
	GroupBy      string
	IPAddress    string
}

// GetCodeStats retrieves code statistics with permission checks
func (s *ConsoleService) GetCodeStats(ctx context.Context, req GetCodeStatsRequest) (*store.CodeStatsResponse, error) {
	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionStatsView); err != nil {
		s.metrics.RecordError("get_code_stats", "permission_denied")
		return nil, fmt.Errorf("permission denied: %w", err)
	}

	// Create stats request
	statsReq := store.CodeStatsRequest{
		StartTime: req.StartTime,
		EndTime:   req.EndTime,
		GroupBy:   req.GroupBy,
	}

	// Get stats
	response, err := s.store.GetCodeStats(ctx, statsReq)
	if err != nil {
		s.metrics.RecordError("get_code_stats", "store_error")
		return nil, fmt.Errorf("failed to get code stats: %w", err)
	}

	// Log audit event
	s.store.CreateAuditLog(ctx, audit.LogRequest{
		AdminID:   req.AdminContext.UserID,
		Action:    audit.ActionStatsViewed,
		Details:   map[string]interface{}{"group_by": req.GroupBy},
		IPAddress: req.IPAddress,
	})

	s.metrics.RecordRequest("GET", "/stats/codes", "200")
	return response, nil
}

// GetSettingsRequest represents the request for getting settings
type GetSettingsRequest struct {
	AdminContext *rbac.UserContext
	IPAddress    string
}

// GetSettings retrieves system settings with permission checks
func (s *ConsoleService) GetSettings(ctx context.Context, req GetSettingsRequest) (*store.Settings, error) {
	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionSettingsView); err != nil {
		s.metrics.RecordError("get_settings", "permission_denied")
		return nil, fmt.Errorf("permission denied: %w", err)
	}

	// Get settings
	settings, err := s.store.GetSettings(ctx)
	if err != nil {
		s.metrics.RecordError("get_settings", "store_error")
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	// Mask sensitive data
	settings.SMTP.Password = ""
	settings.SMS.AuthToken = ""

	s.metrics.RecordRequest("GET", "/settings", "200")
	return settings, nil
}

// UpdateSettingsRequest represents the request for updating settings
type UpdateSettingsRequest struct {
	AdminContext *rbac.UserContext
	Settings     *store.Settings
	IPAddress    string
}

// UpdateSettings updates system settings with permission checks
func (s *ConsoleService) UpdateSettings(ctx context.Context, req UpdateSettingsRequest) error {
	// Check rate limit
	if !s.rateLimiter.Allow() {
		s.metrics.RecordError("update_settings", "rate_limit_exceeded")
		return fmt.Errorf("rate limit exceeded")
	}

	// Check permissions
	if err := s.rbacGuard.CheckPermission(ctx, req.AdminContext, rbac.PermissionSettingsUpdate); err != nil {
		s.metrics.RecordError("update_settings", "permission_denied")
		return fmt.Errorf("permission denied: %w", err)
	}

	// Update settings
	if err := s.store.UpdateSettings(ctx, req.Settings); err != nil {
		s.metrics.RecordError("update_settings", "store_error")
		return fmt.Errorf("failed to update settings: %w", err)
	}

	// Log audit event
	s.store.CreateAuditLog(ctx, audit.LogRequest{
		AdminID:   req.AdminContext.UserID,
		Action:    audit.ActionSettingsUpdate,
		Details:   map[string]interface{}{"updated_at": time.Now()},
		IPAddress: req.IPAddress,
	})

	s.metrics.RecordSettingsUpdate(req.AdminContext.UserID, "all")
	s.metrics.RecordRequest("PUT", "/settings", "200")
	return nil
}
