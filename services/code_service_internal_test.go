package services

import (
	"context"
	"testing"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/internal/testdb"
	"github.com/all2prosperity/auth_service/models"

	"github.com/rs/zerolog"
)

func newTestCodeService(t *testing.T, isProd bool) *CodeService {
	t.Helper()
	db := testdb.New(t)
	sec := &config.SecurityConfig{
		TestBypassCode:   "159357",
		EnableTestBypass: true,
		CodeMaxAttempts:  3,
	}
	logger := zerolog.New(zerolog.NewConsoleWriter()).Level(zerolog.Disabled)
	svc, err := NewCodeService(db, &config.SMTPConfig{}, &config.SMSConfig{}, sec, "test-hmac-key", isProd, logger)
	if err != nil {
		t.Fatalf("new code service: %v", err)
	}
	return svc
}

func TestCodeService_StoresHMACNotPlaintext(t *testing.T) {
	svc := newTestCodeService(t, false)
	const id, code = "user@example.com", "123456"

	if err := svc.storeCode(id, models.CodeChannelEmail, code); err != nil {
		t.Fatalf("store: %v", err)
	}

	var row models.CodeLoginToken
	if err := svc.db.Where("identifier = ?", id).First(&row).Error; err != nil {
		t.Fatalf("read row: %v", err)
	}
	if row.Code == code {
		t.Fatal("verification code stored in plaintext")
	}
	if row.Code != svc.hashCode(code) {
		t.Fatal("stored value is not the expected HMAC of the code")
	}
}

func TestCodeService_VerifySuccess(t *testing.T) {
	svc := newTestCodeService(t, false)
	const id, code = "user@example.com", "654321"
	if err := svc.storeCode(id, models.CodeChannelEmail, code); err != nil {
		t.Fatalf("store: %v", err)
	}

	ok, err := svc.VerifyCode(id, models.CodeChannelEmail, code)
	if err != nil || !ok {
		t.Fatalf("verify should succeed, got ok=%v err=%v", ok, err)
	}

	// Code is single-use: a second verify fails.
	ok, _ = svc.VerifyCode(id, models.CodeChannelEmail, code)
	if ok {
		t.Fatal("code should be consumed after first successful verify")
	}
}

func TestCodeService_WrongCodeIncrementsAttempts(t *testing.T) {
	svc := newTestCodeService(t, false)
	const id, code = "user@example.com", "111111"
	if err := svc.storeCode(id, models.CodeChannelEmail, code); err != nil {
		t.Fatalf("store: %v", err)
	}

	if ok, _ := svc.VerifyCode(id, models.CodeChannelEmail, "000000"); ok {
		t.Fatal("wrong code should not verify")
	}

	var row models.CodeLoginToken
	if err := svc.db.Where("identifier = ?", id).First(&row).Error; err != nil {
		t.Fatalf("read row: %v", err)
	}
	if row.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", row.Attempts)
	}
}

func TestCodeService_InvalidatedAfterMaxAttempts(t *testing.T) {
	svc := newTestCodeService(t, false) // CodeMaxAttempts = 3
	const id, code = "user@example.com", "222222"
	if err := svc.storeCode(id, models.CodeChannelEmail, code); err != nil {
		t.Fatalf("store: %v", err)
	}

	for i := 0; i < 3; i++ {
		if ok, _ := svc.VerifyCode(id, models.CodeChannelEmail, "999999"); ok {
			t.Fatal("wrong code should not verify")
		}
	}

	// After reaching the attempt cap, even the correct code is rejected.
	if ok, _ := svc.VerifyCode(id, models.CodeChannelEmail, code); ok {
		t.Fatal("code should be invalidated after exceeding max attempts")
	}
}

func TestCodeService_TestBypassGating(t *testing.T) {
	// Non-production with bypass enabled: the code is accepted without any row.
	dev := newTestCodeService(t, false)
	if ok, _ := dev.VerifyCode("anyone@example.com", models.CodeChannelEmail, "159357"); !ok {
		t.Fatal("test bypass code should be accepted in non-production")
	}

	// Production: the bypass is never active, regardless of config.
	prod := newTestCodeService(t, true)
	if ok, _ := prod.VerifyCode("anyone@example.com", models.CodeChannelEmail, "159357"); ok {
		t.Fatal("test bypass code must be rejected in production")
	}
}

func TestCodeService_SendRateLimited(t *testing.T) {
	svc := newTestCodeService(t, false)
	ctx := context.Background()
	const email = "rate@example.com"

	if err := svc.SendEmailCode(ctx, email, "Login"); err != nil {
		t.Fatalf("first send should succeed: %v", err)
	}
	// A second send within the interval is rejected.
	if err := svc.SendEmailCode(ctx, email, "Login"); err == nil {
		t.Fatal("second send within interval should be rate limited")
	}
}
