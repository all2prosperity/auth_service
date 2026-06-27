// Package testsupport provides shared, infra-free test fixtures: an in-memory
// SQLite database and a miniredis-backed Redis client. It is imported only by
// black-box (_test) packages to avoid import cycles with the packages it wires.
package testsupport

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/core"
	"github.com/all2prosperity/auth_service/dao"
	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/internal/testdb"
	"github.com/all2prosperity/auth_service/services"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

// NewDB returns an in-memory SQLite database wrapped as *database.DB with all
// models migrated.
func NewDB(t *testing.T) *database.DB { return testdb.New(t) }

// RawDB exposes the underlying *gorm.DB for direct row assertions.
func RawDB(db *database.DB) *gorm.DB { return testdb.Raw(db) }

// NewRedis returns a Redis client backed by an in-process miniredis instance.
func NewRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
		mr.Close()
	})
	return client
}

// NewSecurity returns a security config tuned for tests: low thresholds so
// lockout/attempt limits trigger quickly, and the gated test bypass enabled.
func NewSecurity() *config.SecurityConfig {
	return &config.SecurityConfig{
		TestBypassCode:    "159357",
		EnableTestBypass:  true,
		LoginMaxAttempts:  3,
		LoginLockDuration: 15 * time.Minute,
		CodeMaxAttempts:   3,
	}
}

// NewJWTConfig returns a JWT config with strong-enough secrets for tests.
func NewJWTConfig() *config.JWTConfig {
	return &config.JWTConfig{
		AccessSecret:    "test-access-secret-which-is-long-enough!!",
		RefreshSecret:   "test-refresh-secret-which-is-long-enough!",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 168 * time.Hour,
		Issuer:          "auth-service-test",
	}
}

// Deps bundles the constructed services so individual tests can reach them.
type Deps struct {
	DB        *database.DB
	Redis     *redis.Client
	JWT       *services.JWTService
	Blacklist *services.TokenBlacklist
	Core      *core.AuthCore
	Security  *config.SecurityConfig
}

// NewCore wires a fully functional AuthCore over SQLite + miniredis with real
// services (JWT + blacklist, code, registration-code), running in non-prod mode.
func NewCore(t *testing.T) *Deps {
	t.Helper()

	db := NewDB(t)
	rdb := NewRedis(t)
	sec := NewSecurity()
	jwtCfg := NewJWTConfig()
	logger := zerolog.New(zerolog.NewConsoleWriter()).Level(zerolog.Disabled)
	stdLogger := log.New(os.Stderr, "", 0)

	jwt := services.NewJWTService(jwtCfg)
	blacklist := services.NewTokenBlacklist(rdb, jwtCfg.RefreshTokenTTL)
	jwt.SetBlacklist(blacklist)

	codeSvc, err := services.NewCodeService(db, &config.SMTPConfig{}, &config.SMSConfig{}, sec, jwtCfg.AccessSecret, false, logger)
	if err != nil {
		t.Fatalf("code service: %v", err)
	}
	regSvc, err := services.NewRegistrationCodeService(rdb, &config.SMSConfig{}, sec, false, logger)
	if err != nil {
		t.Fatalf("registration code service: %v", err)
	}

	authCore := core.NewAuthCore(
		db,
		dao.NewUserDAO(db),
		dao.NewLoginAttemptDAO(db),
		services.NewPasswordService(),
		jwt,
		codeSvc,
		regSvc,
		blacklist,
		sec,
		stdLogger,
	)

	return &Deps{
		DB:        db,
		Redis:     rdb,
		JWT:       jwt,
		Blacklist: blacklist,
		Core:      authCore,
		Security:  sec,
	}
}
