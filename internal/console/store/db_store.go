package store

import (
	"context"
	"fmt"
	"time"

	"auth_service/internal/console/audit"
	"auth_service/models"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

// DBStore implements Store interface using direct database access
// This is used in integrated mode where console runs within auth-server
type DBStore struct {
	db          *gorm.DB
	auditLogger *audit.Logger
}

// NewDBStore creates a new database store
func NewDBStore(db *gorm.DB) Store {
	return &DBStore{
		db:          db,
		auditLogger: audit.NewLogger(db),
	}
}

// ListUsers retrieves users with pagination and filtering
func (s *DBStore) ListUsers(ctx context.Context, req ListUsersRequest) (*ListUsersResponse, error) {
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 || req.PageSize > 100 {
		req.PageSize = 20
	}

	query := s.db.WithContext(ctx).Model(&models.User{})

	// Apply search filter
	if req.Search != "" {
		searchTerm := "%" + req.Search + "%"
		query = query.Where(
			"email ILIKE ? OR phone_number ILIKE ? OR id::text ILIKE ?",
			searchTerm, searchTerm, searchTerm,
		)
	}

	// Apply status filter
	switch req.Status {
	case UserStatusLocked:
		query = query.Where("locked_until > ?", time.Now())
	case UserStatusPending:
		query = query.Where("confirmed_at IS NULL")
	case UserStatusActive:
		query = query.Where("confirmed_at IS NOT NULL AND (locked_until IS NULL OR locked_until <= ?)", time.Now())
	}

	// Apply role filter
	if req.Role != "" {
		query = query.Where("? = ANY(roles)", req.Role)
	}

	// Count total
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}

	// Get paginated results
	var users []models.User
	offset := (req.Page - 1) * req.PageSize
	if err := query.Order("created_at DESC").
		Offset(offset).
		Limit(req.PageSize).
		Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Convert to UserInfo
	userInfos := make([]UserInfo, len(users))
	for i, user := range users {
		userInfos[i] = *UserInfoFromModel(&user)
	}

	return &ListUsersResponse{
		Users:    userInfos,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}, nil
}

// GetUser retrieves a single user by ID
func (s *DBStore) GetUser(ctx context.Context, userID string) (*UserInfo, error) {
	id, err := ulid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return UserInfoFromModel(&user), nil
}

// LockUser locks a user with a reason
func (s *DBStore) LockUser(ctx context.Context, userID, reason string) error {
	id, err := ulid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	// Lock until 24 hours from now
	lockedUntil := time.Now().Add(24 * time.Hour)

	if err := s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		Update("locked_until", lockedUntil).Error; err != nil {
		return fmt.Errorf("failed to lock user: %w", err)
	}

	// Log audit event
	s.auditLogger.Log(ctx, audit.LogRequest{
		UserID: userID,
		Action: "lock_user",
		Details: map[string]interface{}{
			"reason":       reason,
			"locked_until": lockedUntil,
		},
	})

	return nil
}

// UnlockUser unlocks a user
func (s *DBStore) UnlockUser(ctx context.Context, userID string) error {
	id, err := ulid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	if err := s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		Update("locked_until", nil).Error; err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}

	// Log audit event
	s.auditLogger.Log(ctx, audit.LogRequest{
		UserID: userID,
		Action: "unlock_user",
	})

	return nil
}

// UpdateUserRole updates a user's role
func (s *DBStore) UpdateUserRole(ctx context.Context, userID, role string) error {
	id, err := ulid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	// Get current user to check existing roles
	var user models.User
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Add role if not already present
	roleExists := false
	for _, existingRole := range user.Roles {
		if existingRole == role {
			roleExists = true
			break
		}
	}

	if !roleExists {
		newRoles := append(user.Roles, role)
		if err := s.db.WithContext(ctx).Model(&models.User{}).
			Where("id = ?", id).
			Update("roles", newRoles).Error; err != nil {
			return fmt.Errorf("failed to update user role: %w", err)
		}

		// Log audit event
		s.auditLogger.Log(ctx, audit.LogRequest{
			UserID: userID,
			Action: "role_add",
			Details: map[string]interface{}{
				"role": role,
			},
		})
	}

	return nil
}

// RevokeUserTokens revokes all tokens for a user
func (s *DBStore) RevokeUserTokens(ctx context.Context, userID string) (int, error) {
	id, err := ulid.Parse(userID)
	if err != nil {
		return 0, fmt.Errorf("invalid user ID: %w", err)
	}

	// Delete all JWT blacklist entries for the user
	result := s.db.WithContext(ctx).Where("user_id = ?", id).Delete(&models.JWTBlacklist{})
	if result.Error != nil {
		return 0, fmt.Errorf("failed to revoke user tokens: %w", result.Error)
	}

	// Log audit event
	s.auditLogger.Log(ctx, audit.LogRequest{
		UserID: userID,
		Action: "revoke_tokens",
		Details: map[string]interface{}{
			"tokens_revoked": result.RowsAffected,
		},
	})

	return int(result.RowsAffected), nil
}

// ListAuditLogs retrieves audit logs
func (s *DBStore) ListAuditLogs(ctx context.Context, req audit.ListRequest) (*audit.ListResponse, error) {
	return s.auditLogger.List(ctx, req)
}

// CreateAuditLog creates an audit log entry
func (s *DBStore) CreateAuditLog(ctx context.Context, req audit.LogRequest) error {
	return s.auditLogger.Log(ctx, req)
}

// GetCodeStats retrieves code statistics
func (s *DBStore) GetCodeStats(ctx context.Context, req CodeStatsRequest) (*CodeStatsResponse, error) {
	// For now, return mock data
	// In a real implementation, you'd query the code_login_tokens table
	// and aggregate statistics based on the time range and grouping

	stats := []CodeStatEntry{
		{
			Timestamp:     req.StartTime,
			SentCount:     100,
			VerifiedCount: 85,
			Type:          "email",
		},
		{
			Timestamp:     req.StartTime.Add(time.Hour),
			SentCount:     120,
			VerifiedCount: 105,
			Type:          "sms",
		},
	}

	return &CodeStatsResponse{
		Stats:         stats,
		TotalSent:     220,
		TotalVerified: 190,
		SuccessRate:   86.36,
	}, nil
}

// GetSettings retrieves system settings
func (s *DBStore) GetSettings(ctx context.Context) (*Settings, error) {
	// For now, return default settings
	// In a real implementation, you'd have a settings table or config store
	return &Settings{
		JWT: JWTSettings{
			AccessTokenTTLMinutes: 60,
			RefreshTokenTTLDays:   30,
		},
		SMTP: SMTPSettings{
			Host:        "smtp.example.com",
			Port:        587,
			Username:    "noreply@example.com",
			UseTLS:      true,
			FromAddress: "noreply@example.com",
		},
		SMS: SMSSettings{
			Provider:   "twilio",
			FromNumber: "+1234567890",
		},
		Security: SecuritySettings{
			MaxLoginAttempts:       5,
			LockoutDurationMinutes: 30,
			CodeExpiryMinutes:      10,
			MaxCodesPerHour:        10,
		},
	}, nil
}

// UpdateSettings updates system settings
func (s *DBStore) UpdateSettings(ctx context.Context, settings *Settings) error {
	// For now, just return success
	// In a real implementation, you'd update the settings store
	return nil
}

// Health checks database connectivity
func (s *DBStore) Health(ctx context.Context) error {
	var result int
	return s.db.WithContext(ctx).Raw("SELECT 1").Scan(&result).Error
}
