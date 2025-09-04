package store

import (
	"context"
	"time"

	"auth_service/internal/console/audit"
	"auth_service/models"
)

// Store defines the interface for console data operations
// This abstraction allows switching between direct DB access (integrated mode)
// and RPC calls (standalone mode)
type Store interface {
	// User operations
	ListUsers(ctx context.Context, req ListUsersRequest) (*ListUsersResponse, error)
	GetUser(ctx context.Context, userID string) (*UserInfo, error)
	LockUser(ctx context.Context, userID, reason string) error
	UnlockUser(ctx context.Context, userID string) error
	UpdateUserRole(ctx context.Context, userID, role string) error
	RevokeUserTokens(ctx context.Context, userID string) (int, error)

	// Audit operations
	ListAuditLogs(ctx context.Context, req audit.ListRequest) (*audit.ListResponse, error)
	CreateAuditLog(ctx context.Context, req audit.LogRequest) error

	// Code statistics
	GetCodeStats(ctx context.Context, req CodeStatsRequest) (*CodeStatsResponse, error)

	// Settings operations
	GetSettings(ctx context.Context) (*Settings, error)
	UpdateSettings(ctx context.Context, settings *Settings) error

	// Health check
	Health(ctx context.Context) error
}

// ListUsersRequest represents request parameters for user listing
type ListUsersRequest struct {
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Search   string     `json:"search,omitempty"`
	Status   UserStatus `json:"status,omitempty"`
	Role     string     `json:"role,omitempty"`
}

// ListUsersResponse represents response for user listing
type ListUsersResponse struct {
	Users    []UserInfo `json:"users"`
	Total    int64      `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
}

// UserInfo represents user information for console
type UserInfo struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	PhoneNumber   string     `json:"phone_number,omitempty"`
	Role          string     `json:"role"`
	Status        UserStatus `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLogin     *time.Time `json:"last_login,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	PhoneVerified bool       `json:"phone_verified"`
	LockedUntil   *time.Time `json:"locked_until,omitempty"`
	LockReason    string     `json:"lock_reason,omitempty"`
}

// UserStatus represents user status
type UserStatus int

const (
	UserStatusUnspecified UserStatus = iota
	UserStatusActive
	UserStatusInactive
	UserStatusLocked
	UserStatusPending
)

// String returns string representation of UserStatus
func (s UserStatus) String() string {
	switch s {
	case UserStatusActive:
		return "active"
	case UserStatusInactive:
		return "inactive"
	case UserStatusLocked:
		return "locked"
	case UserStatusPending:
		return "pending"
	default:
		return "unspecified"
	}
}

// CodeStatsRequest represents request for code statistics
type CodeStatsRequest struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	GroupBy   string    `json:"group_by"` // hour, day, week
}

// CodeStatsResponse represents response for code statistics
type CodeStatsResponse struct {
	Stats         []CodeStatEntry `json:"stats"`
	TotalSent     int             `json:"total_sent"`
	TotalVerified int             `json:"total_verified"`
	SuccessRate   float64         `json:"success_rate"`
}

// CodeStatEntry represents a single code statistics entry
type CodeStatEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	SentCount     int       `json:"sent_count"`
	VerifiedCount int       `json:"verified_count"`
	Type          string    `json:"type"` // sms, email
}

// Settings represents system settings
type Settings struct {
	JWT      JWTSettings      `json:"jwt"`
	SMTP     SMTPSettings     `json:"smtp"`
	SMS      SMSSettings      `json:"sms"`
	Security SecuritySettings `json:"security"`
}

// JWTSettings represents JWT configuration
type JWTSettings struct {
	AccessTokenTTLMinutes int `json:"access_token_ttl_minutes"`
	RefreshTokenTTLDays   int `json:"refresh_token_ttl_days"`
}

// SMTPSettings represents SMTP configuration
type SMTPSettings struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"` // encrypted
	UseTLS      bool   `json:"use_tls"`
	FromAddress string `json:"from_address"`
}

// SMSSettings represents SMS configuration
type SMSSettings struct {
	Provider   string `json:"provider"`
	AccountSID string `json:"account_sid"`
	AuthToken  string `json:"auth_token,omitempty"` // encrypted
	FromNumber string `json:"from_number"`
}

// SecuritySettings represents security configuration
type SecuritySettings struct {
	MaxLoginAttempts       int `json:"max_login_attempts"`
	LockoutDurationMinutes int `json:"lockout_duration_minutes"`
	CodeExpiryMinutes      int `json:"code_expiry_minutes"`
	MaxCodesPerHour        int `json:"max_codes_per_hour"`
}

// UserStatusFromString converts string to UserStatus
func UserStatusFromString(s string) UserStatus {
	switch s {
	case "active":
		return UserStatusActive
	case "inactive":
		return UserStatusInactive
	case "locked":
		return UserStatusLocked
	case "pending":
		return UserStatusPending
	default:
		return UserStatusUnspecified
	}
}

// UserInfoFromModel converts models.User to UserInfo
func UserInfoFromModel(user *models.User) *UserInfo {
	// Handle optional fields
	email := ""
	if user.Email != nil {
		email = *user.Email
	}

	phoneNumber := ""
	if user.PhoneNumber != nil {
		phoneNumber = *user.PhoneNumber
	}

	var lockedUntil *time.Time
	if user.LockedUntil != nil && !user.LockedUntil.IsZero() {
		lockedUntil = user.LockedUntil
	}

	// Determine user status
	status := UserStatusActive
	if user.IsLocked() {
		status = UserStatusLocked
	} else if !user.IsConfirmed() {
		status = UserStatusPending
	}

	// Get primary role (first role or default)
	role := "user"
	if len(user.Roles) > 0 {
		role = user.Roles[0]
	}

	return &UserInfo{
		ID:            user.ID,
		Email:         email,
		PhoneNumber:   phoneNumber,
		Role:          role,
		Status:        status,
		CreatedAt:     user.CreatedAt,
		LastLogin:     nil, // Not tracked in current model
		EmailVerified: user.IsConfirmed(),
		PhoneVerified: user.IsConfirmed(),
		LockedUntil:   lockedUntil,
		LockReason:    "", // Not tracked in current model
	}
}
