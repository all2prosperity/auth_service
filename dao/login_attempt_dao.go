package dao

import (
	"fmt"
	"time"

	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/models"

	"gorm.io/gorm"
)

// LoginAttemptDAO tracks failed login attempts per (identifier, IP) for
// brute-force protection.
type LoginAttemptDAO struct {
	db *database.DB
}

// NewLoginAttemptDAO creates a new LoginAttemptDAO.
func NewLoginAttemptDAO(db *database.DB) *LoginAttemptDAO {
	return &LoginAttemptDAO{db: db}
}

// Get returns the attempt record for an (identifier, IP) pair, or nil if none.
func (dao *LoginAttemptDAO) Get(identifier, ip string) (*models.LoginAttempt, error) {
	var attempt models.LoginAttempt
	result := dao.db.Where("identifier = ? AND ip = ?", identifier, ip).First(&attempt)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get login attempt: %w", result.Error)
	}
	return &attempt, nil
}

// RecordFailure increments the failed-attempt counter for an (identifier, IP)
// pair, locking it for lockDuration once attempts reach maxAttempts. It returns
// the resulting record so callers can tell whether a lock was applied.
func (dao *LoginAttemptDAO) RecordFailure(identifier, ip string, maxAttempts int, lockDuration time.Duration) (*models.LoginAttempt, error) {
	attempt, err := dao.Get(identifier, ip)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if attempt == nil {
		attempt = &models.LoginAttempt{
			Identifier:  identifier,
			IP:          ip,
			Attempts:    1,
			LastAttempt: now,
		}
		if attempt.ShouldBeLocked(maxAttempts) {
			until := now.Add(lockDuration)
			attempt.LockedUntil = &until
		}
		if err := dao.db.Create(attempt).Error; err != nil {
			return nil, fmt.Errorf("failed to create login attempt: %w", err)
		}
		return attempt, nil
	}

	attempt.Attempts++
	attempt.LastAttempt = now
	if attempt.ShouldBeLocked(maxAttempts) {
		until := now.Add(lockDuration)
		attempt.LockedUntil = &until
	}
	if err := dao.db.Save(attempt).Error; err != nil {
		return nil, fmt.Errorf("failed to update login attempt: %w", err)
	}
	return attempt, nil
}

// Reset clears the attempt record for an (identifier, IP) pair after a
// successful login.
func (dao *LoginAttemptDAO) Reset(identifier, ip string) error {
	result := dao.db.Where("identifier = ? AND ip = ?", identifier, ip).Delete(&models.LoginAttempt{})
	if result.Error != nil {
		return fmt.Errorf("failed to reset login attempt: %w", result.Error)
	}
	return nil
}
