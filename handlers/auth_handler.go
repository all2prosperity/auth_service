package handlers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/all2prosperity/auth_service/dao"
	"github.com/all2prosperity/auth_service/database"
	authv1 "github.com/all2prosperity/auth_service/generated/auth/v1"
	"github.com/all2prosperity/auth_service/models"
	"github.com/all2prosperity/auth_service/services"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuthHandler implements the AuthService
type AuthHandler struct {
	userDAO         *dao.UserDAO
	passwordService *services.PasswordService
	jwtService      *services.JWTService
	codeService     *services.CodeService
	regCodeService  *services.RegistrationCodeService
	logger          *log.Logger
	db              *database.DB
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
	db *database.DB,
	userDAO *dao.UserDAO,
	passwordService *services.PasswordService,
	jwtService *services.JWTService,
	codeService *services.CodeService,
	regCodeService *services.RegistrationCodeService,
	logger *log.Logger,
) *AuthHandler {
	return &AuthHandler{
		userDAO:         userDAO,
		passwordService: passwordService,
		jwtService:      jwtService,
		codeService:     codeService,
		regCodeService:  regCodeService,
		logger:          logger,
		db:              db,
	}
}

// Register implements user registration
func (h *AuthHandler) Register(
	ctx context.Context,
	req *connect.Request[authv1.RegisterRequest],
) (*connect.Response[authv1.RegisterResponse], error) {

	// Validate password strength
	if err := h.passwordService.IsStrongPassword(req.Msg.Password); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("weak password: %w", err))
	}

	// Extract identifier
	var email, phoneNumber *string
	switch identifier := req.Msg.Identifier.(type) {
	case *authv1.RegisterRequest_Email:
		email = &identifier.Email
	case *authv1.RegisterRequest_PhoneNumber:
		phoneNumber = &identifier.PhoneNumber
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("email or phone number required"))
	}

	// Check if user already exists
	var existingUser *models.User
	var err error
	if email != nil {
		existingUser, err = h.userDAO.GetUserByEmail(*email)
	} else {
		existingUser, err = h.userDAO.GetUserByPhoneNumber(*phoneNumber)
	}

	if err == nil && existingUser != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("user already exists"))
	}

	// Hash password
	hashedPassword, err := h.passwordService.HashPassword(req.Msg.Password)
	if err != nil {
		h.logger.Printf("Failed to hash password: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to process password"))
	}

	// Create user
	user := &models.User{
		Email:        email,
		PhoneNumber:  phoneNumber,
		PasswordHash: &hashedPassword,
		Roles:        []string{"user"},
	}

	// For email registration, user needs to confirm
	// For phone registration, we can auto-confirm for now
	if phoneNumber != nil {
		now := time.Now()
		user.ConfirmedAt = &now
	}

	err = h.userDAO.CreateUser(user)
	if err != nil {
		h.logger.Printf("Failed to create user: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create user"))
	}

	// Generate tokens
	accessToken, refreshToken, err := h.jwtService.GenerateTokenPair(user)
	if err != nil {
		h.logger.Printf("Failed to generate tokens: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate tokens"))
	}

	// Log audit event
	h.logAuditEvent(ctx, user.ID, models.AuditActionRegister, nil)

	return connect.NewResponse(&authv1.RegisterResponse{
		User: &authv1.UserInfo{
			UserId:  user.ID,
			Roles:   user.Roles,
			Created: timestamppb.New(user.CreatedAt),
		},
		Tokens: &authv1.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}), nil
}

// Login implements user login with password
func (h *AuthHandler) Login(
	ctx context.Context,
	req *connect.Request[authv1.LoginRequest],
) (*connect.Response[authv1.LoginResponse], error) {

	// Extract identifier
	var identifier string
	switch id := req.Msg.Identifier.(type) {
	case *authv1.LoginRequest_Email:
		identifier = id.Email
	case *authv1.LoginRequest_PhoneNumber:
		identifier = id.PhoneNumber
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("email or phone number required"))
	}

	// Get user
	user, err := h.userDAO.GetUserByIdentifier(identifier)
	if err != nil {
		h.logAuditEvent(ctx, "", models.AuditActionLoginFail, map[string]interface{}{
			"identifier": identifier,
			"reason":     "user not found",
		})
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid credentials"))
	}

	// Check if user is locked
	if user.IsLocked() {
		h.logAuditEvent(ctx, user.ID, models.AuditActionLoginFail, map[string]interface{}{
			"reason": "user locked",
		})
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("account is locked"))
	}

	// Verify password
	if user.PasswordHash == nil {
		h.logAuditEvent(ctx, user.ID, models.AuditActionLoginFail, map[string]interface{}{
			"reason": "no password set",
		})
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid credentials"))
	}

	valid, err := h.passwordService.VerifyPassword(req.Msg.Password, *user.PasswordHash)
	if err != nil {
		h.logger.Printf("Failed to verify password: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("authentication failed"))
	}

	if !valid {
		h.logAuditEvent(ctx, user.ID, models.AuditActionLoginFail, map[string]interface{}{
			"reason": "invalid password",
		})
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid credentials"))
	}

	// Generate tokens
	accessToken, refreshToken, err := h.jwtService.GenerateTokenPair(user)
	if err != nil {
		h.logger.Printf("Failed to generate tokens: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate tokens"))
	}

	// Log successful login
	h.logAuditEvent(ctx, user.ID, models.AuditActionLoginSuccess, nil)

	return connect.NewResponse(&authv1.LoginResponse{
		User: &authv1.UserInfo{
			UserId:  user.ID,
			Roles:   user.Roles,
			Created: timestamppb.New(user.CreatedAt),
		},
		Tokens: &authv1.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}), nil
}

// RefreshToken implements token refresh
func (h *AuthHandler) RefreshToken(
	ctx context.Context,
	req *connect.Request[authv1.RefreshTokenRequest],
) (*connect.Response[authv1.RefreshTokenResponse], error) {

	// Validate refresh token
	claims, err := h.jwtService.ValidateRefreshToken(req.Msg.RefreshToken)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid refresh token"))
	}

	// Get user
	userID := claims.UserID
	user, err := h.userDAO.GetUserByID(userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found"))
	}

	// Check if user is locked
	if user.IsLocked() {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("account is locked"))
	}

	// Generate new token pair
	accessToken, refreshToken, err := h.jwtService.RefreshTokenPair(req.Msg.RefreshToken, user)
	if err != nil {
		h.logger.Printf("Failed to refresh tokens: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to refresh tokens"))
	}

	return connect.NewResponse(&authv1.RefreshTokenResponse{
		Tokens: &authv1.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}), nil
}

// Logout implements user logout
func (h *AuthHandler) Logout(
	ctx context.Context,
	req *connect.Request[authv1.LogoutRequest],
) (*connect.Response[authv1.LogoutResponse], error) {

	// Extract token from context (this would be set by middleware)
	token := h.extractTokenFromContext(ctx)
	if token != "" {
		// Extract token ID and blacklist it
		userID, err := h.jwtService.ExtractUserID(token)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token: %w", err))
		}
		if userID != "" {
			// In a real implementation, you'd extract the JTI and expiration
			// and add it to blacklist
			h.logAuditEvent(ctx, userID, models.AuditActionLogout, nil)
		}
	}

	return connect.NewResponse(&authv1.LogoutResponse{}), nil
}

// GetMe returns current user information
func (h *AuthHandler) GetMe(
	ctx context.Context,
	req *connect.Request[authv1.GetMeRequest],
) (*connect.Response[authv1.GetMeResponse], error) {

	// Extract token from request headers
	authHeader := req.Header().Get("Authorization")
	if authHeader == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing authorization header"))
	}

	// Extract token
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid authorization header format"))
	}

	// Validate token and extract user ID
	claims, err := h.jwtService.ValidateAccessToken(token)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token: %w", err))
	}

	userID := claims.UserID
	user, err := h.userDAO.GetUserByID(userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found"))
	}

	return connect.NewResponse(&authv1.GetMeResponse{
		User: &authv1.UserInfo{
			UserId:  user.ID,
			Roles:   user.Roles,
			Created: timestamppb.New(user.CreatedAt),
		},
	}), nil
}

// StartPasswordReset initiates password reset process
func (h *AuthHandler) StartPasswordReset(
	ctx context.Context,
	req *connect.Request[authv1.StartPasswordResetRequest],
) (*connect.Response[emptypb.Empty], error) {

	// Extract identifier
	var identifier string
	switch id := req.Msg.Identifier.(type) {
	case *authv1.StartPasswordResetRequest_Email:
		identifier = id.Email
		// Send email code
		err := h.codeService.SendEmailCode(ctx, identifier, "Password Reset")
		if err != nil {
			h.logger.Printf("Failed to send password reset email: %v", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send reset code"))
		}
	case *authv1.StartPasswordResetRequest_PhoneNumber:
		identifier = id.PhoneNumber
		// Send SMS code
		err := h.codeService.SendSMSCode(ctx, identifier, "Password Reset")
		if err != nil {
			h.logger.Printf("Failed to send password reset SMS: %v", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send reset code"))
		}
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("email or phone number required"))
	}

	// Log audit event
	h.logAuditEvent(ctx, "", models.AuditActionPasswordResetRequest, map[string]interface{}{
		"identifier": identifier,
	})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

// CompletePasswordReset completes the password reset process
func (h *AuthHandler) CompletePasswordReset(
	ctx context.Context,
	req *connect.Request[authv1.CompletePasswordResetRequest],
) (*connect.Response[emptypb.Empty], error) {

	// This is a simplified implementation
	// In practice, you'd validate the token and update the password
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// StartCodeLogin initiates code-based login
func (h *AuthHandler) StartCodeLogin(
	ctx context.Context,
	req *connect.Request[authv1.StartCodeLoginRequest],
) (*connect.Response[emptypb.Empty], error) {

	// Extract identifier
	var identifier string
	switch id := req.Msg.Identifier.(type) {
	case *authv1.StartCodeLoginRequest_Email:
		identifier = id.Email
		err := h.codeService.SendEmailCode(ctx, identifier, "Login")
		if err != nil {
			h.logger.Printf("Failed to send login email code: %v", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send login code"))
		}
	case *authv1.StartCodeLoginRequest_PhoneNumber:
		identifier = id.PhoneNumber
		err := h.codeService.SendSMSCode(ctx, identifier, "Login")
		if err != nil {
			h.logger.Printf("Failed to send login SMS code: %v", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send login code"))
		}
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("email or phone number required"))
	}

	// Log audit event
	h.logAuditEvent(ctx, "", models.AuditActionCodeLoginStart, map[string]interface{}{
		"identifier": identifier,
	})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

// CompleteCodeLogin completes code-based login
func (h *AuthHandler) CompleteCodeLogin(
	ctx context.Context,
	req *connect.Request[authv1.CompleteCodeLoginRequest],
) (*connect.Response[authv1.CompleteCodeLoginResponse], error) {

	// Extract identifier
	var identifier string
	var channel models.CodeChannel
	switch id := req.Msg.Identifier.(type) {
	case *authv1.CompleteCodeLoginRequest_Email:
		identifier = id.Email
		channel = models.CodeChannelEmail
	case *authv1.CompleteCodeLoginRequest_PhoneNumber:
		identifier = id.PhoneNumber
		channel = models.CodeChannelSMS
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("email or phone number required"))
	}

	// Verify code
	valid, err := h.codeService.VerifyCode(identifier, channel, req.Msg.Code)
	if err != nil {
		h.logger.Printf("Failed to verify code: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to verify code"))
	}

	if !valid {
		h.logAuditEvent(ctx, "", models.AuditActionLoginFail, map[string]interface{}{
			"identifier": identifier,
			"reason":     "invalid code",
		})
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid or expired code"))
	}

	// Get or create user
	user, err := h.userDAO.GetUserByIdentifier(identifier)
	if err != nil {
		// Create new user for code login
		user = &models.User{
			Roles: []string{"user"},
		}

		if channel == models.CodeChannelEmail {
			user.Email = &identifier
		} else {
			user.PhoneNumber = &identifier
		}

		// Auto-confirm for code login
		now := time.Now()
		user.ConfirmedAt = &now

		err = h.userDAO.CreateUser(user)
		if err != nil {
			h.logger.Printf("Failed to create user: %v", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create user"))
		}
	}

	// Check if user is locked
	if user.IsLocked() {
		h.logAuditEvent(ctx, user.ID, models.AuditActionLoginFail, map[string]interface{}{
			"reason": "user locked",
		})
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("account is locked"))
	}

	// Generate tokens
	accessToken, refreshToken, err := h.jwtService.GenerateTokenPair(user)
	if err != nil {
		h.logger.Printf("Failed to generate tokens: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate tokens"))
	}

	// Log successful login
	h.logAuditEvent(ctx, user.ID, models.AuditActionCodeLoginComplete, nil)

	return connect.NewResponse(&authv1.CompleteCodeLoginResponse{
		User: &authv1.UserInfo{
			UserId:  user.ID,
			Roles:   user.Roles,
			Created: timestamppb.New(user.CreatedAt),
		},
		Tokens: &authv1.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}), nil
}

// StartCodeRegister initiates SMS-based registration by sending verification code
func (h *AuthHandler) StartCodeRegister(
	ctx context.Context,
	req *connect.Request[authv1.StartCodeRegisterRequest],
) (*connect.Response[emptypb.Empty], error) {
	phone := req.Msg.PhoneNumber
	if strings.TrimSpace(phone) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("phone number is required"))
	}

	if err := h.regCodeService.SendPhoneRegisterCode(ctx, phone); err != nil {
		h.logger.Printf("Failed to send registration SMS code: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send registration code"))
	}

	// Audit log (generic register start)
	h.logAuditEvent(ctx, "", models.AuditActionRegister, map[string]interface{}{
		"phone": phone,
		"step":  "start",
	})

	return connect.NewResponse(&emptypb.Empty{}), nil
}

// CompleteCodeRegister completes SMS-based registration with code verification and password set
func (h *AuthHandler) CompleteCodeRegister(
	ctx context.Context,
	req *connect.Request[authv1.CompleteCodeRegisterRequest],
) (*connect.Response[authv1.CompleteCodeRegisterResponse], error) {
	phone := strings.TrimSpace(req.Msg.PhoneNumber)
	code := strings.TrimSpace(req.Msg.Code)
	password := req.Msg.Password

	if phone == "" || code == "" || password == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("phone, code and password are required"))
	}

	// Password policy
	if err := h.passwordService.IsStrongPassword(password); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("weak password: %w", err))
	}

	// Verify code
	valid, err := h.regCodeService.VerifyPhoneRegisterCode(ctx, phone, code)
	if err != nil {
		h.logger.Printf("Failed to verify registration code: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to verify code"))
	}
	if !valid {
		h.logAuditEvent(ctx, "", models.AuditActionLoginFail, map[string]interface{}{
			"identifier": phone,
			"reason":     "invalid code",
		})
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid or expired code"))
	}

	// Ensure user does not already exist
	if existing, err := h.userDAO.GetUserByPhoneNumber(phone); err == nil && existing != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("user already exists"))
	}

	// Hash password
	hashedPassword, err := h.passwordService.HashPassword(password)
	if err != nil {
		h.logger.Printf("Failed to hash password: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to process password"))
	}

	// Create user
	phoneCopy := phone
	now := time.Now()
	user := &models.User{
		PhoneNumber:  &phoneCopy,
		PasswordHash: &hashedPassword,
		Roles:        []string{"user"},
		ConfirmedAt:  &now,
	}
	if err := h.userDAO.CreateUser(user); err != nil {
		h.logger.Printf("Failed to create user: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create user"))
	}

	// Issue tokens
	accessToken, refreshToken, err := h.jwtService.GenerateTokenPair(user)
	if err != nil {
		h.logger.Printf("Failed to generate tokens: %v", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate tokens"))
	}

	// Audit
	h.logAuditEvent(ctx, user.ID, models.AuditActionRegister, map[string]interface{}{
		"method": "sms_code",
	})

	return connect.NewResponse(&authv1.CompleteCodeRegisterResponse{
		User: &authv1.UserInfo{
			UserId:  user.ID,
			Roles:   user.Roles,
			Created: timestamppb.New(user.CreatedAt),
		},
		Tokens: &authv1.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}), nil
}

// Helper functions

func (h *AuthHandler) extractTokenFromContext(ctx context.Context) string {
	// For Connect-RPC, we need to extract from the request headers
	// This is a simplified implementation - in production you'd use interceptors
	return ""
}

func (h *AuthHandler) extractUserIDFromContext(ctx context.Context) string {
	// For Connect-RPC, we need to extract from the request headers
	// This is a simplified implementation - in production you'd use interceptors
	return ""
}

func (h *AuthHandler) logAuditEvent(ctx context.Context, userID string, action models.AuditAction, extra map[string]interface{}) {
	// Implementation for audit logging
}
