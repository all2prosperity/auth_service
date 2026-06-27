package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/all2prosperity/auth_service/internal/testsupport"
	"github.com/all2prosperity/auth_service/models"
	"github.com/all2prosperity/auth_service/services"
)

func testUser() *models.User {
	return &models.User{
		BaseModel: models.BaseModel{ID: "01HZZZZZZZZZZZZZZZZZZZZZZZ"},
		Roles:     []string{"user"},
	}
}

func TestJWT_GenerateValidateRoundtrip(t *testing.T) {
	jwt := services.NewJWTService(testsupport.NewJWTConfig())
	user := testUser()

	access, refresh, err := jwt.GenerateTokenPair(user)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	claims, err := jwt.ValidateAccessToken(access)
	if err != nil {
		t.Fatalf("validate access: %v", err)
	}
	if claims.UserID != user.ID {
		t.Fatalf("claims user = %s, want %s", claims.UserID, user.ID)
	}

	if _, err := jwt.ValidateRefreshToken(refresh); err != nil {
		t.Fatalf("validate refresh: %v", err)
	}
}

func TestJWT_RejectsTamperedToken(t *testing.T) {
	jwt := services.NewJWTService(testsupport.NewJWTConfig())
	access, _, err := jwt.GenerateTokenPair(testUser())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := jwt.ValidateAccessToken(access + "tamper"); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestJWT_RejectsExpiredToken(t *testing.T) {
	cfg := testsupport.NewJWTConfig()
	cfg.AccessTokenTTL = time.Millisecond
	jwt := services.NewJWTService(cfg)

	access, _, err := jwt.GenerateTokenPair(testUser())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := jwt.ValidateAccessToken(access); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestJWT_RefreshRotationRevokesOldToken(t *testing.T) {
	rdb := testsupport.NewRedis(t)
	cfg := testsupport.NewJWTConfig()
	jwt := services.NewJWTService(cfg)
	jwt.SetBlacklist(services.NewTokenBlacklist(rdb, cfg.RefreshTokenTTL))
	user := testUser()

	_, refresh, err := jwt.GenerateTokenPair(user)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Rotate: produces a new pair and revokes the presented refresh token.
	if _, _, err := jwt.RefreshTokenPair(refresh, user); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Replaying the old refresh token must now be rejected (reuse detection).
	if _, err := jwt.ValidateRefreshToken(refresh); err == nil {
		t.Fatal("expected reused refresh token to be rejected after rotation")
	}
}

func TestJWT_RevokeUserInvalidatesAccessToken(t *testing.T) {
	rdb := testsupport.NewRedis(t)
	cfg := testsupport.NewJWTConfig()
	jwt := services.NewJWTService(cfg)
	bl := services.NewTokenBlacklist(rdb, cfg.RefreshTokenTTL)
	jwt.SetBlacklist(bl)
	user := testUser()

	access, _, err := jwt.GenerateTokenPair(user)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Valid before revocation.
	if _, err := jwt.ValidateAccessToken(access); err != nil {
		t.Fatalf("token should be valid before revoke: %v", err)
	}

	if _, err := bl.RevokeUser(context.Background(), user.ID); err != nil {
		t.Fatalf("revoke user: %v", err)
	}

	// The previously issued token now carries a stale epoch and is rejected.
	if _, err := jwt.ValidateAccessToken(access); err == nil {
		t.Fatal("expected access token to be rejected after user revoke")
	}
}
