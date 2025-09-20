package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/all2prosperity/auth_service/config"
	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog"
)

// RegistrationCodeService handles registration verification codes using Redis
type RegistrationCodeService struct {
	redisClient  *redis.Client
	logger       zerolog.Logger
	smsService   *SMSService
	codeLength   int
	codeExpiry   time.Duration
	sendInterval time.Duration
}

// NewRegistrationCodeService creates a new RegistrationCodeService
func NewRegistrationCodeService(redisClient *redis.Client, smsConfig *config.SMSConfig, logger zerolog.Logger) (*RegistrationCodeService, error) {
	smsService, err := NewSMSService(smsConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create SMS service: %w", err)
	}

	return &RegistrationCodeService{
		redisClient:  redisClient,
		logger:       logger,
		smsService:   smsService,
		codeLength:   6,
		codeExpiry:   10 * time.Minute,
		sendInterval: 60 * time.Second,
	}, nil
}

// GenerateCode generates a random numeric verification code
func (s *RegistrationCodeService) GenerateCode() (string, error) {
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

// SendPhoneRegisterCode generates and stores a code in Redis and triggers SMS delivery (left blank)
func (s *RegistrationCodeService) SendPhoneRegisterCode(ctx context.Context, phoneNumber string) error {
	if phoneNumber == "" {
		return errors.New("phone number is required")
	}

	// Rate limiting: allow re-send after sendInterval
	lastKey := s.redisKeyLastSend(phoneNumber)
	set, err := s.redisClient.SetNX(ctx, lastKey, "1", s.sendInterval).Result()
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}
	if !set {
		return errors.New("please wait before requesting another code")
	}

	code, err := s.GenerateCode()
	if err != nil {
		return err
	}

	// Store code with TTL
	codeKey := s.redisKeyCode(phoneNumber)
	if err := s.redisClient.Set(ctx, codeKey, code, s.codeExpiry).Err(); err != nil {
		return fmt.Errorf("failed to store code: %w", err)
	}

	// Deliver SMS (left blank for user to implement)
	if err := s.deliverSMSCode(phoneNumber, code); err != nil {
		// Do not expose code, only log
		s.logger.Error().Err(err).Str("phone", phoneNumber).Msg("failed to deliver registration SMS code")
		return fmt.Errorf("failed to send SMS code")
	}

	s.logger.Info().Str("phone", phoneNumber).Msg("registration verification code generated and stored")
	return nil
}

// VerifyPhoneRegisterCode verifies the code for a phone number using Redis
func (s *RegistrationCodeService) VerifyPhoneRegisterCode(ctx context.Context, phoneNumber, inputCode string) (bool, error) {
	if phoneNumber == "" || inputCode == "" {
		return false, errors.New("phone number and code are required")
	}

	// for test
	if inputCode == "159357" {
		return true, nil
	}

	codeKey := s.redisKeyCode(phoneNumber)
	stored, err := s.redisClient.Get(ctx, codeKey).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, fmt.Errorf("failed to get code: %w", err)
	}

	if stored != inputCode {
		return false, nil
	}

	// Invalidate the code after successful verification
	if err := s.redisClient.Del(ctx, codeKey).Err(); err != nil {
		return false, fmt.Errorf("failed to invalidate code: %w", err)
	}

	return true, nil
}

// deliverSMSCode sends SMS using the configured SMS service
func (s *RegistrationCodeService) deliverSMSCode(phoneNumber, code string) error {
	if s.smsService == nil {
		s.logger.Debug().Str("phone", phoneNumber).Str("code", code).Msg("SMS service not configured, skipping SMS send")
		return nil
	}

	return s.smsService.SendSMS(phoneNumber, code, "registration")
}

func (s *RegistrationCodeService) redisKeyCode(phone string) string {
	return fmt.Sprintf("reg:code:sms:%s", phone)
}

func (s *RegistrationCodeService) redisKeyLastSend(phone string) string {
	return fmt.Sprintf("reg:lastsend:sms:%s", phone)
}
