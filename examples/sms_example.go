package main

import (
	"fmt"
	"log"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/services"
	"github.com/rs/zerolog"
)

// Example of how to use the SMS service
func main() {
	// Load configuration
	cfg, err := config.LoadConfig("configs/local.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create logger
	logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()

	// Create SMS service
	smsService, err := services.NewSMSService(&cfg.SMS, logger)
	if err != nil {
		log.Fatalf("Failed to create SMS service: %v", err)
	}

	// Example: Send verification code
	phoneNumber := "17611103594"
	code := "123456"
	purpose := "registration"

	fmt.Printf("Sending SMS to %s with code %s for %s...\n", phoneNumber, code, purpose)

	err = smsService.SendSMS(phoneNumber, code, purpose)
	if err != nil {
		log.Printf("Failed to send SMS: %v", err)
	} else {
		fmt.Println("SMS sent successfully!")
	}
}
