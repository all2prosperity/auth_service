package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Base model with common fields
type BaseModel struct {
	ID        string     `gorm:"type:varchar(26);primaryKey" json:"id"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`
}

// StringArray represents a PostgreSQL string array
type StringArray []string

// Value implements the driver.Valuer interface
func (s StringArray) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return "{" + joinStrings(s, ",") + "}", nil
}

// Scan implements the sql.Scanner interface
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}

	switch v := value.(type) {
	case string:
		*s = parseStringArray(v)
		return nil
	case []byte:
		*s = parseStringArray(string(v))
		return nil
	default:
		return errors.New("cannot scan into StringArray")
	}
}

// User represents a user in the system
type User struct {
	BaseModel
	Email        *string                     `gorm:"type:text;uniqueIndex" json:"email,omitempty"`
	PhoneNumber  *string                     `gorm:"type:text;uniqueIndex;column:phone_number" json:"phone_number,omitempty"`
	PasswordHash *string                     `gorm:"type:text;column:password_hash" json:"-"`
	Roles        datatypes.JSONSlice[string] `gorm:"default:'[\"user\"]'" json:"roles"`
	ConfirmedAt  *time.Time                  `gorm:"column:confirmed_at" json:"confirmed_at,omitempty"`
	LockedUntil  *time.Time                  `gorm:"column:locked_until" json:"locked_until,omitempty"`

	// Relationships
	SocialAccounts      []SocialAccount      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"social_accounts,omitempty"`
	PasswordResetTokens []PasswordResetToken `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
	JWTBlacklist        []JWTBlacklist       `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
	AuditLogs           []AuditLog           `gorm:"foreignKey:UserID" json:"-"`
}

// TableName specifies the table name for User model
func (User) TableName() string {
	return "users"
}

// IsLocked returns true if the user is currently locked
func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

// IsConfirmed returns true if the user has confirmed their email/phone
func (u *User) IsConfirmed() bool {
	return u.ConfirmedAt != nil
}

// HasRole returns true if the user has the specified role
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// BeforeCreate GORM hook
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = ulid.Make().String()
	}
	if len(u.Roles) == 0 {
		u.Roles = datatypes.JSONSlice[string]{"user"}
	}
	return nil
}

// SocialAccount represents a social login binding
type SocialAccount struct {
	BaseModel
	UserID      string `gorm:"type:varchar(26);not null;index" json:"user_id"`
	Provider    string `gorm:"type:varchar(100);not null" json:"provider"`
	ProviderUID string `gorm:"type:varchar(200);not null;column:provider_uid;uniqueIndex:idx_provider_uid" json:"provider_uid"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for SocialAccount model
func (SocialAccount) TableName() string {
	return "social_accounts"
}

// JWTBlacklist represents a blacklisted JWT token
type JWTBlacklist struct {
	BaseModel
	TokenID   string    `gorm:"type:text;not null;uniqueIndex;column:token_id" json:"token_id"`
	UserID    *string   `gorm:"type:varchar(26);index" json:"user_id,omitempty"`
	ExpiresAt time.Time `gorm:"not null;index;column:expires_at" json:"expires_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for JWTBlacklist model
func (JWTBlacklist) TableName() string {
	return "jwt_blacklist"
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	BaseModel
	UserID    string    `gorm:"type:varchar(26);not null;index" json:"user_id"`
	Token     string    `gorm:"type:text;not null;uniqueIndex" json:"token"`
	ExpiresAt time.Time `gorm:"not null;index;column:expires_at" json:"expires_at"`
	Used      bool      `gorm:"default:false" json:"used"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for PasswordResetToken model
func (PasswordResetToken) TableName() string {
	return "password_reset_tokens"
}

// IsExpired returns true if the token has expired
func (p *PasswordResetToken) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// IsValid returns true if the token is valid (not used and not expired)
func (p *PasswordResetToken) IsValid() bool {
	return !p.Used && !p.IsExpired()
}

// CodeChannel represents the channel used for code delivery
type CodeChannel string

const (
	CodeChannelEmail CodeChannel = "email"
	CodeChannelSMS   CodeChannel = "sms"
)

// CodeLoginToken represents a one-time code for login
type CodeLoginToken struct {
	BaseModel
	Identifier string      `gorm:"type:text;not null;index" json:"identifier"`
	Channel    CodeChannel `gorm:"type:code_channel;not null" json:"channel"`
	Code       string      `gorm:"type:text;not null;uniqueIndex:idx_identifier_code_channel,priority:2" json:"code"`
	ExpiresAt  time.Time   `gorm:"not null;index;column:expires_at" json:"expires_at"`
	Used       bool        `gorm:"default:false" json:"used"`
}

// TableName specifies the table name for CodeLoginToken model
func (CodeLoginToken) TableName() string {
	return "code_login_tokens"
}

// IsExpired returns true if the code has expired
func (c *CodeLoginToken) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsValid returns true if the code is valid (not used and not expired)
func (c *CodeLoginToken) IsValid() bool {
	return !c.Used && !c.IsExpired()
}

// AuditAction represents an audit action type
type AuditAction string

const (
	AuditActionLoginSuccess          AuditAction = "login_success"
	AuditActionLoginFail             AuditAction = "login_fail"
	AuditActionRegister              AuditAction = "register"
	AuditActionPasswordResetRequest  AuditAction = "password_reset_request"
	AuditActionPasswordResetComplete AuditAction = "password_reset_complete"
	AuditActionOAuthLogin            AuditAction = "oauth_login"
	AuditActionLogout                AuditAction = "logout"
	AuditActionRoleAdd               AuditAction = "role_add"
	AuditActionRoleRemove            AuditAction = "role_remove"
	AuditActionLockUser              AuditAction = "lock_user"
	AuditActionUnlockUser            AuditAction = "unlock_user"
	AuditActionCodeLoginStart        AuditAction = "code_login_start"
	AuditActionCodeLoginComplete     AuditAction = "code_login_complete"
)

// JSONB represents a JSONB column type
type JSONB map[string]interface{}

// Value implements the driver.Valuer interface
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, j)
}

// AuditLog represents an audit log entry
type AuditLog struct {
	BaseModel
	UserID    *string     `gorm:"type:varchar(26);index" json:"user_id,omitempty"`
	Action    AuditAction `gorm:"type:audit_action;not null;index" json:"action"`
	IP        *string     `gorm:"type:inet" json:"ip,omitempty"`
	UserAgent *string     `gorm:"type:text;column:user_agent" json:"user_agent,omitempty"`
	Extra     JSONB       `gorm:"type:jsonb" json:"extra,omitempty"`

	// Relationships
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for AuditLog model
func (AuditLog) TableName() string {
	return "audit_logs"
}

// LoginAttempt tracks login attempts for rate limiting
type LoginAttempt struct {
	Identifier  string     `gorm:"type:text;not null;primaryKey" json:"identifier"`
	IP          string     `gorm:"type:text;not null;primaryKey" json:"ip"`
	Attempts    int        `gorm:"default:1" json:"attempts"`
	LastAttempt time.Time  `gorm:"autoUpdateTime;column:last_attempt" json:"last_attempt"`
	LockedUntil *time.Time `gorm:"column:locked_until;index" json:"locked_until,omitempty"`
}

// TableName specifies the table name for LoginAttempt model
func (LoginAttempt) TableName() string {
	return "login_attempts"
}

// IsLocked returns true if the IP/identifier is currently locked
func (l *LoginAttempt) IsLocked() bool {
	return l.LockedUntil != nil && l.LockedUntil.After(time.Now())
}

// ShouldBeLocked returns true if the attempts exceed the threshold
func (l *LoginAttempt) ShouldBeLocked(maxAttempts int) bool {
	return l.Attempts >= maxAttempts
}

// Helper functions for StringArray

func joinStrings(s []string, sep string) string {
	if len(s) == 0 {
		return ""
	}
	if len(s) == 1 {
		return s[0]
	}
	result := s[0]
	for i := 1; i < len(s); i++ {
		result += sep + s[i]
	}
	return result
}

func parseStringArray(s string) []string {
	if s == "" || s == "{}" {
		return []string{}
	}
	// Remove braces
	if len(s) > 1 && s[0] == '{' && s[len(s)-1] == '}' {
		s = s[1 : len(s)-1]
	}
	if s == "" {
		return []string{}
	}
	// Simple split by comma (this is a simplified version)
	result := []string{}
	parts := splitByComma(s)
	for _, part := range parts {
		result = append(result, part)
	}
	return result
}

func splitByComma(s string) []string {
	if s == "" {
		return []string{}
	}
	result := []string{}
	current := ""
	for _, char := range s {
		if char == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(char)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
