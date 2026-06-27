package core

import "time"

// UserInfo is the transport-agnostic representation of a user returned to callers.
type UserInfo struct {
	UserID  string
	Roles   []string
	Created time.Time
}

// TokenPair holds an access/refresh token pair.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// AuthResult is returned by flows that authenticate a user and issue tokens.
type AuthResult struct {
	User   UserInfo
	Tokens TokenPair
}

// RegisterInput registers a user with email or phone plus a password.
type RegisterInput struct {
	Email    string
	Phone    string
	Password string
}

// LoginInput authenticates with email or phone plus a password. IP is supplied
// by the transport adapter for brute-force tracking.
type LoginInput struct {
	Email    string
	Phone    string
	Password string
	IP       string
}

// RefreshInput exchanges a refresh token for a new token pair.
type RefreshInput struct {
	RefreshToken string
}

// IdentifierInput carries an email-or-phone identifier for code/reset flows.
type IdentifierInput struct {
	Email string
	Phone string
}

// CompletePasswordResetInput finalizes a password reset.
type CompletePasswordResetInput struct {
	Token       string
	NewPassword string
}

// CompleteCodeLoginInput finalizes passwordless code login.
type CompleteCodeLoginInput struct {
	Email string
	Phone string
	Code  string
}

// StartCodeRegisterInput begins SMS-based registration.
type StartCodeRegisterInput struct {
	Phone string
}

// CompleteCodeRegisterInput finalizes SMS-based registration with a password.
type CompleteCodeRegisterInput struct {
	Phone    string
	Code     string
	Password string
}
