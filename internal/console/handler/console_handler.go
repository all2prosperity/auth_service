package handler

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"auth_service/internal/console/rbac"
	"auth_service/internal/console/service"

	"github.com/golang-jwt/jwt/v5"
)

// ConsoleHandler handles HTTP/gRPC requests for console operations
type ConsoleHandler struct {
	service   *service.ConsoleService
	jwtSecret string
}

// NewConsoleHandler creates a new console handler
func NewConsoleHandler(service *service.ConsoleService, jwtSecret string) *ConsoleHandler {
	return &ConsoleHandler{
		service:   service,
		jwtSecret: jwtSecret,
	}
}

// extractUserContext extracts user context from JWT token
func (h *ConsoleHandler) extractUserContext(ctx context.Context, r *http.Request) (*rbac.UserContext, error) {
	// Get authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	// Extract token
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("missing user ID in token")
	}

	email, _ := claims["email"].(string)

	// Extract roles
	var roles []string
	if rolesInterface, ok := claims["roles"]; ok {
		if rolesList, ok := rolesInterface.([]interface{}); ok {
			for _, role := range rolesList {
				if roleStr, ok := role.(string); ok {
					roles = append(roles, roleStr)
				}
			}
		}
	}

	// Check if user has admin role
	hasAdminRole := false
	for _, role := range roles {
		if role == "admin" || role == "secops" || role == "support" {
			hasAdminRole = true
			break
		}
	}

	if !hasAdminRole {
		return nil, fmt.Errorf("user does not have required admin privileges")
	}

	return &rbac.UserContext{
		UserID: userID,
		Roles:  roles,
		Email:  email,
	}, nil
}

// getClientIP extracts client IP address from request
func (h *ConsoleHandler) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// parseTimeParam parses time parameter from query string
func parseTimeParam(param string) (time.Time, error) {
	if param == "" {
		return time.Time{}, nil
	}

	// Try ISO format first
	if t, err := time.Parse(time.RFC3339, param); err == nil {
		return t, nil
	}

	// Try Unix timestamp
	if timestamp, err := strconv.ParseInt(param, 10, 64); err == nil {
		return time.Unix(timestamp, 0), nil
	}

	return time.Time{}, fmt.Errorf("invalid time format")
}

// REST handlers for console operations
// These can be used when not using gRPC/Connect

// HandleListUsers handles GET /admin/users
func (h *ConsoleHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract user context
	userCtx, err := h.extractUserContext(ctx, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	pageSize, _ := strconv.Atoi(query.Get("page_size"))
	search := query.Get("search")
	status := query.Get("status")
	role := query.Get("role")

	// Create request
	req := service.ListUsersRequest{
		AdminContext: userCtx,
		Page:         page,
		PageSize:     pageSize,
		Search:       search,
		Status:       status,
		Role:         role,
		IPAddress:    h.getClientIP(r),
	}

	// Call service
	response, err := h.service.ListUsers(ctx, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// In a real implementation, you'd use a JSON encoder here
	fmt.Fprintf(w, `{"users": %v, "total": %d, "page": %d, "page_size": %d}`,
		response.Users, response.Total, response.Page, response.PageSize)
}

// HandleGetUser handles GET /admin/users/{id}
func (h *ConsoleHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract user context
	userCtx, err := h.extractUserContext(ctx, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		return
	}

	// Extract user ID from URL
	// In a real implementation, you'd use a router to extract path parameters
	userID := r.URL.Path[len("/admin/users/"):]

	// Create request
	req := service.GetUserRequest{
		AdminContext: userCtx,
		UserID:       userID,
		IPAddress:    h.getClientIP(r),
	}

	// Call service
	user, err := h.service.GetUser(ctx, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// In a real implementation, you'd use a JSON encoder here
	fmt.Fprintf(w, `{"user": %v}`, user)
}

// HandleLockUser handles POST /admin/users/{id}/lock
func (h *ConsoleHandler) HandleLockUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract user context
	userCtx, err := h.extractUserContext(ctx, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		return
	}

	// Extract user ID from URL
	userID := extractUserIDFromPath(r.URL.Path, "/admin/users/", "/lock")
	reason := r.FormValue("reason")

	// Create request
	req := service.LockUserRequest{
		AdminContext: userCtx,
		UserID:       userID,
		Reason:       reason,
		IPAddress:    h.getClientIP(r),
	}

	// Call service
	if err := h.service.LockUser(ctx, req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"success": true, "message": "User locked successfully"}`)
}

// HandleUnlockUser handles POST /admin/users/{id}/unlock
func (h *ConsoleHandler) HandleUnlockUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract user context
	userCtx, err := h.extractUserContext(ctx, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		return
	}

	// Extract user ID from URL
	userID := extractUserIDFromPath(r.URL.Path, "/admin/users/", "/unlock")
	reason := r.FormValue("reason")

	// Create request
	req := service.UnlockUserRequest{
		AdminContext: userCtx,
		UserID:       userID,
		Reason:       reason,
		IPAddress:    h.getClientIP(r),
	}

	// Call service
	if err := h.service.UnlockUser(ctx, req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"success": true, "message": "User unlocked successfully"}`)
}

// HandleUpdateUserRole handles PUT /admin/users/{id}/role
func (h *ConsoleHandler) HandleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract user context
	userCtx, err := h.extractUserContext(ctx, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		return
	}

	// Extract user ID from URL
	userID := extractUserIDFromPath(r.URL.Path, "/admin/users/", "/role")
	newRole := r.FormValue("role")

	// Create request
	req := service.UpdateUserRoleRequest{
		AdminContext: userCtx,
		UserID:       userID,
		NewRole:      newRole,
		IPAddress:    h.getClientIP(r),
	}

	// Call service
	if err := h.service.UpdateUserRole(ctx, req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"success": true, "message": "User role updated successfully"}`)
}

// HandleRevokeUserTokens handles POST /admin/users/{id}/revoke-tokens
func (h *ConsoleHandler) HandleRevokeUserTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract user context
	userCtx, err := h.extractUserContext(ctx, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		return
	}

	// Extract user ID from URL
	userID := extractUserIDFromPath(r.URL.Path, "/admin/users/", "/revoke-tokens")
	reason := r.FormValue("reason")

	// Create request
	req := service.RevokeUserTokensRequest{
		AdminContext: userCtx,
		UserID:       userID,
		Reason:       reason,
		IPAddress:    h.getClientIP(r),
	}

	// Call service
	count, err := h.service.RevokeUserTokens(ctx, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"success": true, "revoked_count": %d, "message": "Tokens revoked successfully"}`, count)
}

// HandleGetAuditLogs handles GET /admin/audit-logs
func (h *ConsoleHandler) HandleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract user context
	userCtx, err := h.extractUserContext(ctx, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	pageSize, _ := strconv.Atoi(query.Get("page_size"))
	userID := query.Get("user_id")
	action := query.Get("action")

	startTime, _ := parseTimeParam(query.Get("start_time"))
	endTime, _ := parseTimeParam(query.Get("end_time"))

	// Create request
	req := service.GetAuditLogsRequest{
		AdminContext: userCtx,
		Page:         page,
		PageSize:     pageSize,
		UserID:       userID,
		Action:       action,
		StartTime:    startTime,
		EndTime:      endTime,
		IPAddress:    h.getClientIP(r),
	}

	// Call service
	response, err := h.service.GetAuditLogs(ctx, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"logs": %v, "total": %d, "page": %d, "page_size": %d}`,
		response.Logs, response.Total, response.Page, response.PageSize)
}

// Helper function to extract user ID from URL path
func extractUserIDFromPath(path, prefix, suffix string) string {
	// Remove prefix
	withoutPrefix := strings.TrimPrefix(path, prefix)
	// Remove suffix
	userID := strings.TrimSuffix(withoutPrefix, suffix)
	return userID
}

// Middleware for authentication and authorization
func (h *ConsoleHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract user context
		_, err := h.extractUserContext(r.Context(), r)
		if err != nil {
			http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
			return
		}

		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}

// SetupRoutes sets up all console routes
func (h *ConsoleHandler) SetupRoutes(mux *http.ServeMux) {
	// Apply auth middleware to all routes
	mux.Handle("/admin/users", h.AuthMiddleware(http.HandlerFunc(h.HandleListUsers)))
	mux.Handle("/admin/users/", h.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/lock") && r.Method == "POST":
			h.HandleLockUser(w, r)
		case strings.HasSuffix(path, "/unlock") && r.Method == "POST":
			h.HandleUnlockUser(w, r)
		case strings.HasSuffix(path, "/role") && r.Method == "PUT":
			h.HandleUpdateUserRole(w, r)
		case strings.HasSuffix(path, "/revoke-tokens") && r.Method == "POST":
			h.HandleRevokeUserTokens(w, r)
		case r.Method == "GET":
			h.HandleGetUser(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/admin/audit-logs", h.AuthMiddleware(http.HandlerFunc(h.HandleGetAuditLogs)))
}
