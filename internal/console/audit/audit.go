package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

// Logger handles audit logging
type Logger struct {
	db *gorm.DB
}

// NewLogger creates a new audit logger
func NewLogger(db *gorm.DB) *Logger {
	return &Logger{db: db}
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	UserID    string    `gorm:"index;not null" json:"user_id"`       // Target user
	AdminID   string    `gorm:"index;not null" json:"admin_id"`      // Admin who performed action
	Action    string    `gorm:"index;not null" json:"action"`        // Action type
	TargetID  string    `gorm:"index" json:"target_id,omitempty"`    // Resource ID if applicable
	Details   string    `gorm:"type:jsonb" json:"details,omitempty"` // Additional details as JSON
	IPAddress string    `gorm:"not null" json:"ip_address"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// LogRequest represents a log request
type LogRequest struct {
	UserID    string                 `json:"user_id"`
	AdminID   string                 `json:"admin_id"`
	Action    string                 `json:"action"`
	TargetID  string                 `json:"target_id,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent,omitempty"`
}

// Action constants
const (
	ActionUserLocked     = "user_locked"
	ActionUserUnlocked   = "user_unlocked"
	ActionUserRoleUpdate = "user_role_updated"
	ActionTokensRevoked  = "tokens_revoked"
	ActionSettingsUpdate = "settings_updated"
	ActionUserViewed     = "user_viewed"
	ActionAuditViewed    = "audit_viewed"
	ActionStatsViewed    = "stats_viewed"
)

// Log creates an audit log entry
func (l *Logger) Log(ctx context.Context, req LogRequest) error {
	details := ""
	if req.Details != nil && len(req.Details) > 0 {
		if detailsBytes, err := json.Marshal(req.Details); err == nil {
			details = string(detailsBytes)
		}
	}

	auditLog := AuditLog{
		ID:        ulid.Make().String(),
		UserID:    req.UserID,
		AdminID:   req.AdminID,
		Action:    req.Action,
		TargetID:  req.TargetID,
		Details:   details,
		IPAddress: req.IPAddress,
		UserAgent: req.UserAgent,
		CreatedAt: time.Now().UTC(),
	}

	return l.db.WithContext(ctx).Create(&auditLog).Error
}

// ListRequest represents a list request for audit logs
type ListRequest struct {
	Page      int       `json:"page"`
	PageSize  int       `json:"page_size"`
	UserID    string    `json:"user_id,omitempty"`
	AdminID   string    `json:"admin_id,omitempty"`
	Action    string    `json:"action,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
}

// ListResponse represents a list response for audit logs
type ListResponse struct {
	Logs     []AuditLog `json:"logs"`
	Total    int64      `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
}

// List retrieves audit logs with pagination and filtering
func (l *Logger) List(ctx context.Context, req ListRequest) (*ListResponse, error) {
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 || req.PageSize > 100 {
		req.PageSize = 20
	}

	query := l.db.WithContext(ctx).Model(&AuditLog{})

	// Apply filters
	if req.UserID != "" {
		query = query.Where("user_id = ?", req.UserID)
	}
	if req.AdminID != "" {
		query = query.Where("admin_id = ?", req.AdminID)
	}
	if req.Action != "" {
		query = query.Where("action = ?", req.Action)
	}
	if !req.StartTime.IsZero() {
		query = query.Where("created_at >= ?", req.StartTime)
	}
	if !req.EndTime.IsZero() {
		query = query.Where("created_at <= ?", req.EndTime)
	}

	// Count total
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	// Get paginated results
	var logs []AuditLog
	offset := (req.Page - 1) * req.PageSize
	if err := query.Order("created_at DESC").
		Offset(offset).
		Limit(req.PageSize).
		Find(&logs).Error; err != nil {
		return nil, err
	}

	return &ListResponse{
		Logs:     logs,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}, nil
}

// CleanupOldLogs removes audit logs older than the specified duration
func (l *Logger) CleanupOldLogs(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().UTC().Add(-olderThan)
	return l.db.WithContext(ctx).
		Where("created_at < ?", cutoff).
		Delete(&AuditLog{}).Error
}
