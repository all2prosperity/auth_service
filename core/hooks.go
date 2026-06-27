package core

import (
	"context"
	"time"
)

// UserRegistrationInfo contains user information passed to registration callbacks.
type UserRegistrationInfo struct {
	UserID      string
	Email       *string
	PhoneNumber *string
	Roles       []string
	CreatedAt   time.Time
	Method      string // "email", "phone", "sms_code", etc.
}

// RegistrationHook is a callback invoked after successful user registration.
type RegistrationHook func(ctx context.Context, user *UserRegistrationInfo) error
