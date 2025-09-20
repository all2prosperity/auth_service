package services

import (
	"encoding/json"
	"fmt"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dysmsapi20170525 "github.com/alibabacloud-go/dysmsapi-20170525/v5/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	credential "github.com/aliyun/credentials-go/credentials"
	"github.com/all2prosperity/auth_service/config"
	"github.com/rs/zerolog"
)

// SMSService handles SMS sending operations
type SMSService struct {
	config       *config.SMSConfig
	logger       zerolog.Logger
	aliyunClient *dysmsapi20170525.Client
}

// NewSMSService creates a new SMS service
func NewSMSService(smsConfig *config.SMSConfig, logger zerolog.Logger) (*SMSService, error) {
	service := &SMSService{
		config: smsConfig,
		logger: logger,
	}

	// Initialize Aliyun SMS client if provider is aliyun
	if smsConfig.Provider == "aliyun" {
		client, err := service.createAliyunClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create aliyun SMS client: %w", err)
		}
		service.aliyunClient = client
	}

	return service, nil
}

// createAliyunClient creates an Aliyun SMS client
func (s *SMSService) createAliyunClient() (*dysmsapi20170525.Client, error) {
	// Use access key and secret key for authentication
	cred, err := credential.NewCredential(&credential.Config{
		Type:            tea.String("access_key"),
		AccessKeyId:     tea.String(s.config.AliyunAccessKey),
		AccessKeySecret: tea.String(s.config.AliyunSecretKey),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create aliyun credential: %w", err)
	}

	config := &openapi.Config{
		Credential: cred,
	}
	// Endpoint for SMS API
	config.Endpoint = tea.String("dysmsapi.aliyuncs.com")

	client, err := dysmsapi20170525.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create aliyun SMS client: %w", err)
	}

	return client, nil
}

// SendSMS sends an SMS message
func (s *SMSService) SendSMS(phoneNumber, code, purpose string) error {
	switch s.config.Provider {
	case "aliyun":
		return s.sendAliyunSMS(phoneNumber, code, purpose)
	case "twilio":
		return s.sendTwilioSMS(phoneNumber, code, purpose)
	default:
		return fmt.Errorf("unsupported SMS provider: %s", s.config.Provider)
	}
}

// sendAliyunSMS sends SMS using Aliyun SMS service
func (s *SMSService) sendAliyunSMS(phoneNumber, code, purpose string) error {
	if s.aliyunClient == nil {
		return fmt.Errorf("aliyun SMS client not initialized")
	}

	// Prepare template parameters
	templateParam := map[string]string{
		"code": code,
	}
	templateParamJSON, err := json.Marshal(templateParam)
	if err != nil {
		return fmt.Errorf("failed to marshal template parameters: %w", err)
	}

	// Create send SMS request
	sendSmsRequest := &dysmsapi20170525.SendSmsRequest{
		SignName:      tea.String(s.config.AliyunSignName),
		TemplateCode:  tea.String(s.config.AliyunTemplate),
		PhoneNumbers:  tea.String(phoneNumber),
		TemplateParam: tea.String(string(templateParamJSON)),
	}

	// Set runtime options
	runtime := &util.RuntimeOptions{}

	// Send SMS with error handling
	tryErr := func() (_e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()

		response, err := s.aliyunClient.SendSmsWithOptions(sendSmsRequest, runtime)
		if err != nil {
			return err
		}

		// Log response for debugging
		s.logger.Debug().
			Str("phone", phoneNumber).
			Str("request_id", tea.StringValue(response.Body.RequestId)).
			Str("biz_id", tea.StringValue(response.Body.BizId)).
			Str("code", tea.StringValue(response.Body.Code)).
			Str("message", tea.StringValue(response.Body.Message)).
			Msg("Aliyun SMS response")

		// Check if SMS was sent successfully
		if tea.StringValue(response.Body.Code) != "OK" {
			return fmt.Errorf("aliyun SMS failed: %s - %s, bizID: %s",
				tea.StringValue(response.Body.Code),
				tea.StringValue(response.Body.Message),
				tea.StringValue(response.Body.BizId))
		}

		return nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}

		// Log error details
		s.logger.Error().
			Err(tryErr).
			Str("phone", phoneNumber).
			Str("error_message", tea.StringValue(error.Message)).
			Str("error_data", tea.StringValue(error.Data)).
			Msg("Failed to send Aliyun SMS")

		// Parse error data for additional information
		if tea.StringValue(error.Data) != "" {
			var data interface{}
			d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
			if err := d.Decode(&data); err == nil {
				if m, ok := data.(map[string]interface{}); ok {
					if recommend, exists := m["Recommend"]; exists {
						s.logger.Error().
							Str("phone", phoneNumber).
							Interface("recommend", recommend).
							Msg("Aliyun SMS error recommendation")
					}
				}
			}
		}

		return fmt.Errorf("failed to send SMS via Aliyun: %w", tryErr)
	}

	s.logger.Info().
		Str("phone", phoneNumber).
		Str("purpose", purpose).
		Msg("SMS sent successfully via Aliyun")

	return nil
}

// sendTwilioSMS sends SMS using Twilio (placeholder implementation)
func (s *SMSService) sendTwilioSMS(phoneNumber, code, purpose string) error {
	// This is a placeholder implementation
	// In production, you would use the Twilio SDK
	s.logger.Info().
		Str("phone", phoneNumber).
		Str("code", code).
		Str("purpose", purpose).
		Msg("Twilio SMS would be sent (not implemented)")

	return nil
}
