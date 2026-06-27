package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/smtp"
	"time"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/models"

	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

// CodeService handles verification code operations
type CodeService struct {
	db           *database.DB
	smtpConfig   *config.SMTPConfig
	smsConfig    *config.SMSConfig
	smsService   *SMSService
	logger       zerolog.Logger
	codeLength   int
	codeExpiry   time.Duration
	sendInterval time.Duration

	hmacKey     []byte
	maxAttempts int

	// Gated test bypass: accepted only outside production when enabled.
	testBypassCode   string
	enableTestBypass bool
	isProd           bool
}

// NewCodeService creates a new code service
func NewCodeService(db *database.DB, smtpConfig *config.SMTPConfig, smsConfig *config.SMSConfig, securityConfig *config.SecurityConfig, hmacKey string, isProd bool, logger zerolog.Logger) (*CodeService, error) {
	smsService, err := NewSMSService(smsConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create SMS service: %w", err)
	}

	svc := &CodeService{
		db:           db,
		smtpConfig:   smtpConfig,
		smsConfig:    smsConfig,
		smsService:   smsService,
		logger:       logger,
		codeLength:   6,
		codeExpiry:   10 * time.Minute,
		sendInterval: 60 * time.Second,
		hmacKey:      []byte(hmacKey),
		maxAttempts:  5,
		isProd:       isProd,
	}
	if securityConfig != nil {
		svc.testBypassCode = securityConfig.TestBypassCode
		svc.enableTestBypass = securityConfig.EnableTestBypass
		if securityConfig.CodeMaxAttempts > 0 {
			svc.maxAttempts = securityConfig.CodeMaxAttempts
		}
	}
	return svc, nil
}

// hashCode returns the hex-encoded HMAC-SHA256 of a verification code.
func (s *CodeService) hashCode(code string) string {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

// testBypassAllowed reports whether the gated test code should be accepted.
// Never allowed in production, regardless of configuration.
func (s *CodeService) testBypassAllowed(inputCode string) bool {
	return !s.isProd && s.enableTestBypass && s.testBypassCode != "" && inputCode == s.testBypassCode
}

// GenerateCode generates a random numeric code
func (s *CodeService) GenerateCode() (string, error) {
	max := big.NewInt(int64(1))
	for i := 0; i < s.codeLength; i++ {
		max = max.Mul(max, big.NewInt(10))
	}
	max = max.Sub(max, big.NewInt(1))

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate random number: %w", err)
	}

	code := fmt.Sprintf("%0*d", s.codeLength, n.Int64())
	return code, nil
}

// SendEmailCode sends a verification code via email
func (s *CodeService) SendEmailCode(ctx context.Context, email string, purpose string) error {
	// Check if we can send (rate limiting)
	canSend, err := s.canSendCode(email, models.CodeChannelEmail)
	if err != nil {
		return fmt.Errorf("failed to check send rate limit: %w", err)
	}
	if !canSend {
		return fmt.Errorf("please wait before requesting another code")
	}

	// Generate code
	code, err := s.GenerateCode()
	if err != nil {
		return fmt.Errorf("failed to generate code: %w", err)
	}

	// Store code in database
	err = s.storeCode(email, models.CodeChannelEmail, code)
	if err != nil {
		return fmt.Errorf("failed to store code: %w", err)
	}

	// Send email
	err = s.sendEmailWithCode(email, code, purpose)
	if err != nil {
		s.logger.Error().Err(err).Str("email", email).Msg("failed to send email code")
		return fmt.Errorf("failed to send email: %w", err)
	}

	s.logger.Info().Str("email", email).Str("purpose", purpose).Msg("verification code sent via email")
	return nil
}

// SendSMSCode sends a verification code via SMS
func (s *CodeService) SendSMSCode(ctx context.Context, phoneNumber string, purpose string) error {
	// Check if we can send (rate limiting)
	canSend, err := s.canSendCode(phoneNumber, models.CodeChannelSMS)
	if err != nil {
		return fmt.Errorf("failed to check send rate limit: %w", err)
	}
	if !canSend {
		return fmt.Errorf("please wait before requesting another code")
	}

	// Generate code
	code, err := s.GenerateCode()
	if err != nil {
		return fmt.Errorf("failed to generate code: %w", err)
	}

	// Store code in database
	err = s.storeCode(phoneNumber, models.CodeChannelSMS, code)
	if err != nil {
		return fmt.Errorf("failed to store code: %w", err)
	}

	// Send SMS
	err = s.sendSMSWithCode(phoneNumber, code, purpose)
	if err != nil {
		s.logger.Error().Err(err).Str("phone", phoneNumber).Msg("failed to send SMS code")
		return fmt.Errorf("failed to send SMS: %w", err)
	}

	s.logger.Info().Str("phone", phoneNumber).Str("purpose", purpose).Msg("verification code sent via SMS")
	return nil
}

// VerifyCode verifies a code for an identifier
func (s *CodeService) VerifyCode(identifier string, channel models.CodeChannel, inputCode string) (bool, error) {
	// Gated test bypass (non-production only).
	if s.testBypassAllowed(inputCode) {
		s.logger.Warn().Str("identifier", identifier).Msg("code verified via test bypass code")
		return true, nil
	}

	var token models.CodeLoginToken
	res := s.db.Where("identifier = ? AND channel = ? AND used = false", identifier, channel).Order("created_at DESC").Limit(1).First(&token)
	if res.Error != nil {
		if res.Error == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to get code: %w", res.Error)
	}

	// Check if code is expired
	if token.IsExpired() {
		return false, nil
	}

	// Too many failed attempts: invalidate the code to prevent brute-forcing.
	if token.Attempts >= s.maxAttempts {
		if err := s.markCodeAsUsed(token.ID); err != nil {
			return false, fmt.Errorf("failed to invalidate code: %w", err)
		}
		s.logger.Warn().Str("identifier", identifier).Msg("verification code invalidated after too many attempts")
		return false, nil
	}

	// Constant-time compare of HMAC digests.
	if subtle.ConstantTimeCompare([]byte(token.Code), []byte(s.hashCode(inputCode))) != 1 {
		if err := s.db.Model(&models.CodeLoginToken{}).Where("id = ?", token.ID).
			UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error; err != nil {
			s.logger.Error().Err(err).Str("identifier", identifier).Msg("failed to increment code attempts")
		}
		return false, nil
	}

	// Mark code as used
	err := s.markCodeAsUsed(token.ID)
	if err != nil {
		return false, fmt.Errorf("failed to mark code as used: %w", err)
	}

	return true, nil
}

// canSendCode checks if we can send a code (rate limiting)
func (s *CodeService) canSendCode(identifier string, channel models.CodeChannel) (bool, error) {
	var lastSent models.CodeLoginToken
	res := s.db.Where("identifier = ? AND channel = ?", identifier, channel).Order("created_at DESC").Limit(1).First(&lastSent)
	if res.Error != nil {
		if res.Error == gorm.ErrRecordNotFound {
			return true, nil // No previous code sent
		}
		return false, fmt.Errorf("failed to check last send time: %w", res.Error)
	}

	// Check if enough time has passed
	if time.Since(lastSent.CreatedAt) < s.sendInterval {
		return false, nil
	}

	return true, nil
}

// storeCode stores a verification code in the database
func (s *CodeService) storeCode(identifier string, channel models.CodeChannel, code string) error {
	expiresAt := time.Now().Add(s.codeExpiry)
	res := s.db.Create(&models.CodeLoginToken{
		Identifier: identifier,
		Channel:    channel,
		Code:       s.hashCode(code),
		ExpiresAt:  expiresAt,
	})
	if res.Error != nil {
		return fmt.Errorf("failed to store code: %w", res.Error)
	}

	return nil
}

// markCodeAsUsed marks a code as used
func (s *CodeService) markCodeAsUsed(tokenID string) error {
	result := s.db.Model(&models.CodeLoginToken{}).Where("id = ?", tokenID).Update("used", true)
	if result.Error != nil {
		return fmt.Errorf("failed to mark code as used: %w", result.Error)
	}
	return nil
}

// sendEmailWithCode sends an email with verification code
func (s *CodeService) sendEmailWithCode(email, code, purpose string) error {
	if s.smtpConfig.Username == "" || s.smtpConfig.Password == "" {
		s.logger.Debug().Str("email", email).Str("code", code).Msg("SMTP not configured, skipping email send")
		return nil // Skip sending in development
	}

	subject := fmt.Sprintf("Verification Code - %s", purpose)
	body := fmt.Sprintf(`
Hi,

Your verification code is: %s

This code will expire in %d minutes.

If you didn't request this code, please ignore this email.

Best regards,
Auth Service
`, code, int(s.codeExpiry.Minutes()))

	// Prepare message
	message := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", email, subject, body)

	// Setup authentication
	auth := smtp.PlainAuth("", s.smtpConfig.Username, s.smtpConfig.Password, s.smtpConfig.Host)

	// Send email
	addr := fmt.Sprintf("%s:%d", s.smtpConfig.Host, s.smtpConfig.Port)
	err := smtp.SendMail(addr, auth, s.smtpConfig.FromEmail, []string{email}, []byte(message))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// sendSMSWithCode sends an SMS with verification code
func (s *CodeService) sendSMSWithCode(phoneNumber, code, purpose string) error {
	if s.smsService == nil {
		s.logger.Debug().Str("phone", phoneNumber).Str("code", code).Msg("SMS service not configured, skipping SMS send")
		return nil
	}

	return s.smsService.SendSMS(phoneNumber, code, purpose)
}

// CleanupExpiredCodes removes expired codes from the database
func (s *CodeService) CleanupExpiredCodes() error {
	res := s.db.Where("expires_at < now()").Delete(&models.CodeLoginToken{})
	if res.Error != nil {
		return fmt.Errorf("failed to cleanup expired codes: %w", res.Error)
	}
	return nil
}
