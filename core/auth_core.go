// Package core holds the transport-agnostic authentication use cases. It has no
// dependency on any wire protocol (HTTP, Connect, gRPC); transport adapters in
// transport/* translate requests into these calls and results back out.
package core

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/dao"
	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/models"
	"github.com/all2prosperity/auth_service/services"
)

// AuthCore implements the authentication use cases over the shared services/DAOs.
type AuthCore struct {
	db               *database.DB
	userDAO          *dao.UserDAO
	loginAttemptDAO  *dao.LoginAttemptDAO
	passwordService  *services.PasswordService
	jwtService       *services.JWTService
	codeService      *services.CodeService
	regCodeService   *services.RegistrationCodeService
	blacklist        *services.TokenBlacklist
	logger           *log.Logger
	registrationHook RegistrationHook

	loginMaxAttempts  int
	loginLockDuration time.Duration
}

// NewAuthCore wires the use-case layer with its dependencies.
func NewAuthCore(
	db *database.DB,
	userDAO *dao.UserDAO,
	loginAttemptDAO *dao.LoginAttemptDAO,
	passwordService *services.PasswordService,
	jwtService *services.JWTService,
	codeService *services.CodeService,
	regCodeService *services.RegistrationCodeService,
	blacklist *services.TokenBlacklist,
	securityConfig *config.SecurityConfig,
	logger *log.Logger,
) *AuthCore {
	c := &AuthCore{
		db:                db,
		userDAO:           userDAO,
		loginAttemptDAO:   loginAttemptDAO,
		passwordService:   passwordService,
		jwtService:        jwtService,
		codeService:       codeService,
		regCodeService:    regCodeService,
		blacklist:         blacklist,
		logger:            logger,
		loginMaxAttempts:  5,
		loginLockDuration: 15 * time.Minute,
	}
	if securityConfig != nil {
		if securityConfig.LoginMaxAttempts > 0 {
			c.loginMaxAttempts = securityConfig.LoginMaxAttempts
		}
		if securityConfig.LoginLockDuration > 0 {
			c.loginLockDuration = securityConfig.LoginLockDuration
		}
	}
	return c
}

// SetRegistrationHook sets the callback invoked after successful registration.
func (c *AuthCore) SetRegistrationHook(hook RegistrationHook) {
	c.registrationHook = hook
}

// GetRegistrationHook returns the configured registration hook (may be nil).
func (c *AuthCore) GetRegistrationHook() RegistrationHook {
	return c.registrationHook
}

// userToInfo converts a stored user into the transport-agnostic UserInfo.
func userToInfo(u *models.User) UserInfo {
	return UserInfo{
		UserID:  u.ID,
		Roles:   u.Roles,
		Created: u.CreatedAt,
	}
}

func (c *AuthCore) issueTokens(u *models.User) (TokenPair, *Error) {
	access, refresh, err := c.jwtService.GenerateTokenPair(u)
	if err != nil {
		c.logger.Printf("Failed to generate tokens: %v", err)
		return TokenPair{}, errInternal("failed to generate tokens")
	}
	return TokenPair{AccessToken: access, RefreshToken: refresh}, nil
}

// Register creates a new user with email or phone and a password.
func (c *AuthCore) Register(ctx context.Context, in RegisterInput) (*AuthResult, *Error) {
	if err := c.passwordService.IsStrongPassword(in.Password); err != nil {
		return nil, errInvalidArgument("weak password: %v", err)
	}

	email, phone, derr := splitIdentifier(in.Email, in.Phone)
	if derr != nil {
		return nil, derr
	}

	var existing *models.User
	var err error
	if email != nil {
		existing, err = c.userDAO.GetUserByEmail(*email)
	} else {
		existing, err = c.userDAO.GetUserByPhoneNumber(*phone)
	}
	if err == nil && existing != nil {
		return nil, errAlreadyExists("user already exists")
	}

	hashed, err := c.passwordService.HashPassword(in.Password)
	if err != nil {
		c.logger.Printf("Failed to hash password: %v", err)
		return nil, errInternal("failed to process password")
	}

	user := &models.User{
		Email:        email,
		PhoneNumber:  phone,
		PasswordHash: &hashed,
		Roles:        []string{"user"},
	}
	// Phone registrations are auto-confirmed; email requires confirmation.
	if phone != nil {
		now := time.Now()
		user.ConfirmedAt = &now
	}

	if err := c.userDAO.CreateUser(user); err != nil {
		c.logger.Printf("Failed to create user: %v", err)
		return nil, errInternal("failed to create user")
	}

	tokens, terr := c.issueTokens(user)
	if terr != nil {
		return nil, terr
	}

	c.logAuditEvent(ctx, user.ID, models.AuditActionRegister, nil)

	method := "password"
	if email != nil {
		method = "email"
	} else if phone != nil {
		method = "phone"
	}
	c.executeRegistrationHook(ctx, user, method)

	return &AuthResult{User: userToInfo(user), Tokens: tokens}, nil
}

// Login authenticates a user with a password, applying brute-force protection.
func (c *AuthCore) Login(ctx context.Context, in LoginInput) (*AuthResult, *Error) {
	identifier, derr := resolveIdentifier(in.Email, in.Phone)
	if derr != nil {
		return nil, derr
	}

	// Brute-force protection: reject early if this (identifier, IP) is locked.
	if c.loginAttemptDAO != nil {
		if attempt, err := c.loginAttemptDAO.Get(identifier, in.IP); err == nil && attempt != nil && attempt.IsLocked() {
			c.logAuditEvent(ctx, "", models.AuditActionLoginFail, map[string]interface{}{
				"identifier": identifier,
				"reason":     "too many attempts",
			})
			return nil, errResourceExhausted("too many failed attempts, please try again later")
		}
	}

	user, err := c.userDAO.GetUserByIdentifier(identifier)
	if err != nil {
		c.recordLoginFailure(identifier, in.IP)
		c.logAuditEvent(ctx, "", models.AuditActionLoginFail, map[string]interface{}{
			"identifier": identifier,
			"reason":     "user not found",
		})
		return nil, errUnauthenticated("invalid credentials")
	}

	if user.IsLocked() {
		c.logAuditEvent(ctx, user.ID, models.AuditActionLoginFail, map[string]interface{}{
			"reason": "user locked",
		})
		return nil, errPermissionDenied("account is locked")
	}

	if user.PasswordHash == nil {
		c.logAuditEvent(ctx, user.ID, models.AuditActionLoginFail, map[string]interface{}{
			"reason": "no password set",
		})
		return nil, errUnauthenticated("invalid credentials")
	}

	valid, err := c.passwordService.VerifyPassword(in.Password, *user.PasswordHash)
	if err != nil {
		c.logger.Printf("Failed to verify password: %v", err)
		return nil, errInternal("authentication failed")
	}
	if !valid {
		c.recordLoginFailure(identifier, in.IP)
		c.logAuditEvent(ctx, user.ID, models.AuditActionLoginFail, map[string]interface{}{
			"reason": "invalid password",
		})
		return nil, errUnauthenticated("invalid credentials")
	}

	if c.loginAttemptDAO != nil {
		if err := c.loginAttemptDAO.Reset(identifier, in.IP); err != nil {
			c.logger.Printf("Failed to reset login attempts: %v", err)
		}
	}

	tokens, terr := c.issueTokens(user)
	if terr != nil {
		return nil, terr
	}

	c.logAuditEvent(ctx, user.ID, models.AuditActionLoginSuccess, nil)
	return &AuthResult{User: userToInfo(user), Tokens: tokens}, nil
}

// RefreshToken rotates a refresh token into a fresh token pair.
func (c *AuthCore) RefreshToken(ctx context.Context, in RefreshInput) (*TokenPair, *Error) {
	claims, err := c.jwtService.ValidateRefreshToken(in.RefreshToken)
	if err != nil {
		return nil, errUnauthenticated("invalid refresh token")
	}

	user, err := c.userDAO.GetUserByID(claims.UserID)
	if err != nil {
		return nil, errNotFound("user not found")
	}

	if user.IsLocked() {
		return nil, errPermissionDenied("account is locked")
	}

	access, refresh, err := c.jwtService.RefreshTokenPair(in.RefreshToken, user)
	if err != nil {
		c.logger.Printf("Failed to refresh tokens: %v", err)
		return nil, errInternal("failed to refresh tokens")
	}
	return &TokenPair{AccessToken: access, RefreshToken: refresh}, nil
}

// Logout revokes the caller's access token. Claims are read from the context,
// injected by the transport's auth middleware.
func (c *AuthCore) Logout(ctx context.Context) *Error {
	claims := services.ClaimsFromContext(ctx)
	if claims == nil {
		return errUnauthenticated("authentication required")
	}

	if c.blacklist != nil && claims.ExpiresAt != nil {
		ttl := time.Until(claims.ExpiresAt.Time)
		if err := c.blacklist.Revoke(ctx, claims.ID, ttl); err != nil {
			c.logger.Printf("Failed to revoke token on logout: %v", err)
		}
	}

	c.logAuditEvent(ctx, claims.UserID, models.AuditActionLogout, nil)
	return nil
}

// GetMe returns the authenticated caller's profile.
func (c *AuthCore) GetMe(ctx context.Context) (*UserInfo, *Error) {
	claims := services.ClaimsFromContext(ctx)
	if claims == nil {
		return nil, errUnauthenticated("authentication required")
	}
	user, err := c.userDAO.GetUserByID(claims.UserID)
	if err != nil {
		return nil, errNotFound("user not found")
	}
	info := userToInfo(user)
	return &info, nil
}

// StartPasswordReset sends a reset code over email or SMS.
func (c *AuthCore) StartPasswordReset(ctx context.Context, in IdentifierInput) *Error {
	switch {
	case in.Email != "":
		if err := c.codeService.SendEmailCode(ctx, in.Email, "Password Reset"); err != nil {
			c.logger.Printf("Failed to send password reset email: %v", err)
			return errInternal("failed to send reset code")
		}
	case in.Phone != "":
		if err := c.codeService.SendSMSCode(ctx, in.Phone, "Password Reset"); err != nil {
			c.logger.Printf("Failed to send password reset SMS: %v", err)
			return errInternal("failed to send reset code")
		}
	default:
		return errInvalidArgument("email or phone number required")
	}

	c.logAuditEvent(ctx, "", models.AuditActionPasswordResetRequest, map[string]interface{}{
		"identifier": firstNonEmpty(in.Email, in.Phone),
	})
	return nil
}

// CompletePasswordReset finalizes a password reset (currently a stub, matching
// the prior behavior pending full implementation).
func (c *AuthCore) CompletePasswordReset(ctx context.Context, in CompletePasswordResetInput) *Error {
	// TODO: validate the reset token and update the password.
	return nil
}

// StartCodeLogin sends a passwordless login code over email or SMS.
func (c *AuthCore) StartCodeLogin(ctx context.Context, in IdentifierInput) *Error {
	switch {
	case in.Email != "":
		if err := c.codeService.SendEmailCode(ctx, in.Email, "Login"); err != nil {
			c.logger.Printf("Failed to send login email code: %v", err)
			return errInternal("failed to send login code")
		}
	case in.Phone != "":
		if err := c.codeService.SendSMSCode(ctx, in.Phone, "Login"); err != nil {
			c.logger.Printf("Failed to send login SMS code: %v", err)
			return errInternal("failed to send login code")
		}
	default:
		return errInvalidArgument("email or phone number required")
	}

	c.logAuditEvent(ctx, "", models.AuditActionCodeLoginStart, map[string]interface{}{
		"identifier": firstNonEmpty(in.Email, in.Phone),
	})
	return nil
}

// CompleteCodeLogin verifies a login code, creating the user on first login.
func (c *AuthCore) CompleteCodeLogin(ctx context.Context, in CompleteCodeLoginInput) (*AuthResult, *Error) {
	var identifier string
	var channel models.CodeChannel
	switch {
	case in.Email != "":
		identifier, channel = in.Email, models.CodeChannelEmail
	case in.Phone != "":
		identifier, channel = in.Phone, models.CodeChannelSMS
	default:
		return nil, errInvalidArgument("email or phone number required")
	}

	valid, err := c.codeService.VerifyCode(identifier, channel, in.Code)
	if err != nil {
		c.logger.Printf("Failed to verify code: %v", err)
		return nil, errInternal("failed to verify code")
	}
	if !valid {
		c.logAuditEvent(ctx, "", models.AuditActionLoginFail, map[string]interface{}{
			"identifier": identifier,
			"reason":     "invalid code",
		})
		return nil, errUnauthenticated("invalid or expired code")
	}

	user, err := c.userDAO.GetUserByIdentifier(identifier)
	if err != nil {
		// First code login: create the user.
		user = &models.User{Roles: []string{"user"}}
		if channel == models.CodeChannelEmail {
			user.Email = &identifier
		} else {
			user.PhoneNumber = &identifier
		}
		now := time.Now()
		user.ConfirmedAt = &now
		if err := c.userDAO.CreateUser(user); err != nil {
			c.logger.Printf("Failed to create user: %v", err)
			return nil, errInternal("failed to create user")
		}
	}

	if user.IsLocked() {
		c.logAuditEvent(ctx, user.ID, models.AuditActionLoginFail, map[string]interface{}{
			"reason": "user locked",
		})
		return nil, errPermissionDenied("account is locked")
	}

	tokens, terr := c.issueTokens(user)
	if terr != nil {
		return nil, terr
	}

	c.logAuditEvent(ctx, user.ID, models.AuditActionCodeLoginComplete, nil)
	return &AuthResult{User: userToInfo(user), Tokens: tokens}, nil
}

// StartCodeRegister sends an SMS registration code.
func (c *AuthCore) StartCodeRegister(ctx context.Context, in StartCodeRegisterInput) *Error {
	phone := strings.TrimSpace(in.Phone)
	if phone == "" {
		return errInvalidArgument("phone number is required")
	}
	if err := c.regCodeService.SendPhoneRegisterCode(ctx, phone); err != nil {
		c.logger.Printf("Failed to send registration SMS code: %v", err)
		return errInternal("failed to send registration code")
	}
	c.logAuditEvent(ctx, "", models.AuditActionRegister, map[string]interface{}{
		"phone": phone,
		"step":  "start",
	})
	return nil
}

// CompleteCodeRegister verifies an SMS code and creates a user with a password.
func (c *AuthCore) CompleteCodeRegister(ctx context.Context, in CompleteCodeRegisterInput) (*AuthResult, *Error) {
	phone := strings.TrimSpace(in.Phone)
	code := strings.TrimSpace(in.Code)
	if phone == "" || code == "" || in.Password == "" {
		return nil, errInvalidArgument("phone, code and password are required")
	}

	if err := c.passwordService.IsStrongPassword(in.Password); err != nil {
		return nil, errInvalidArgument("weak password: %v", err)
	}

	valid, err := c.regCodeService.VerifyPhoneRegisterCode(ctx, phone, code)
	if err != nil {
		c.logger.Printf("Failed to verify registration code: %v", err)
		return nil, errInternal("failed to verify code")
	}
	if !valid {
		c.logAuditEvent(ctx, "", models.AuditActionLoginFail, map[string]interface{}{
			"identifier": phone,
			"reason":     "invalid code",
		})
		return nil, errUnauthenticated("invalid or expired code")
	}

	if existing, err := c.userDAO.GetUserByPhoneNumber(phone); err == nil && existing != nil {
		return nil, errAlreadyExists("user already exists")
	}

	hashed, err := c.passwordService.HashPassword(in.Password)
	if err != nil {
		c.logger.Printf("Failed to hash password: %v", err)
		return nil, errInternal("failed to process password")
	}

	now := time.Now()
	phoneCopy := phone
	user := &models.User{
		PhoneNumber:  &phoneCopy,
		PasswordHash: &hashed,
		Roles:        []string{"user"},
		ConfirmedAt:  &now,
	}
	if err := c.userDAO.CreateUser(user); err != nil {
		c.logger.Printf("Failed to create user: %v", err)
		return nil, errInternal("failed to create user")
	}

	tokens, terr := c.issueTokens(user)
	if terr != nil {
		return nil, terr
	}

	c.logAuditEvent(ctx, user.ID, models.AuditActionRegister, map[string]interface{}{
		"method": "sms_code",
	})
	c.executeRegistrationHook(ctx, user, "sms_code")

	return &AuthResult{User: userToInfo(user), Tokens: tokens}, nil
}

// --- helpers ---

// recordLoginFailure increments the brute-force counter for an (identifier, IP)
// pair, locking it once the configured threshold is reached.
func (c *AuthCore) recordLoginFailure(identifier, ip string) {
	if c.loginAttemptDAO == nil {
		return
	}
	if _, err := c.loginAttemptDAO.RecordFailure(identifier, ip, c.loginMaxAttempts, c.loginLockDuration); err != nil {
		c.logger.Printf("Failed to record login attempt: %v", err)
	}
}

// executeRegistrationHook runs the registration hook asynchronously if set.
func (c *AuthCore) executeRegistrationHook(ctx context.Context, user *models.User, method string) {
	if c.registrationHook == nil {
		return
	}
	info := &UserRegistrationInfo{
		UserID:      user.ID,
		Email:       user.Email,
		PhoneNumber: user.PhoneNumber,
		Roles:       user.Roles,
		CreatedAt:   user.CreatedAt,
		Method:      method,
	}
	go func() {
		if err := c.registrationHook(ctx, info); err != nil {
			c.logger.Printf("Registration hook failed for user %s: %v", user.ID, err)
		}
	}()
}

// logAuditEvent is a placeholder for audit logging (kept as a no-op to preserve
// call sites; wiring persistent audit storage is tracked separately).
func (c *AuthCore) logAuditEvent(ctx context.Context, userID string, action models.AuditAction, extra map[string]interface{}) {
}

// splitIdentifier validates that exactly one of email/phone is provided and
// returns them as optional pointers (suitable for model fields).
func splitIdentifier(email, phone string) (*string, *string, *Error) {
	email = strings.TrimSpace(email)
	phone = strings.TrimSpace(phone)
	switch {
	case email != "" && phone == "":
		return &email, nil, nil
	case phone != "" && email == "":
		return nil, &phone, nil
	default:
		return nil, nil, errInvalidArgument("exactly one of email or phone number is required")
	}
}

// resolveIdentifier validates that exactly one of email/phone is provided and
// returns it as a single identifier string.
func resolveIdentifier(email, phone string) (string, *Error) {
	e, p, err := splitIdentifier(email, phone)
	if err != nil {
		return "", err
	}
	if e != nil {
		return *e, nil
	}
	return *p, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
