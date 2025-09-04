package database

import (
	"context"
	"fmt"
	"time"

	"auth_service/config"
	"auth_service/models"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB wraps the GORM database connection
type DB struct {
	*gorm.DB
}

// NewDatabase creates a new GORM database connection
func NewDatabase(cfg *config.DatabaseConfig, zapLogger *zap.SugaredLogger) (*DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
	)

	gormConfig := &gorm.Config{
		Logger: logger.New(
			zap.NewStdLog(zapLogger.Desugar()),
			logger.Config{
				SlowThreshold:             time.Second,
				LogLevel:                  logger.Info,
				IgnoreRecordNotFoundError: true,
				Colorful:                  true,
			},
		),
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Get underlying sql.DB for connection pool configuration
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Test the connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{db}, nil
}

// AutoMigrate runs GORM auto migration for all models
func (db *DB) AutoMigrate() error {
	// Create custom types first
	if err := db.createCustomTypes(); err != nil {
		return fmt.Errorf("failed to create custom types: %w", err)
	}

	// Run auto migration
	err := db.DB.AutoMigrate(
		&models.User{},
		&models.SocialAccount{},
		&models.JWTBlacklist{},
		&models.PasswordResetToken{},
		&models.CodeLoginToken{},
		&models.AuditLog{},
		&models.LoginAttempt{},
	)
	if err != nil {
		return fmt.Errorf("failed to auto migrate: %w", err)
	}

	// Create additional indexes
	if err := db.createAdditionalIndexes(); err != nil {
		return fmt.Errorf("failed to create additional indexes: %w", err)
	}

	return nil
}

// createCustomTypes creates custom PostgreSQL types
func (db *DB) createCustomTypes() error {
	// Create enum types
	enumQueries := []string{
		`DO $$ BEGIN
			CREATE TYPE audit_action AS ENUM (
				'login_success', 'login_fail',
				'register', 'password_reset_request', 'password_reset_complete',
				'oauth_login', 'logout',
				'role_add', 'role_remove',
				'lock_user', 'unlock_user',
				'code_login_start', 'code_login_complete'
			);
		EXCEPTION
			WHEN duplicate_object THEN null;
		END $$;`,

		`DO $$ BEGIN
			CREATE TYPE code_channel AS ENUM ('email', 'sms');
		EXCEPTION
			WHEN duplicate_object THEN null;
		END $$;`,
	}

	for _, query := range enumQueries {
		if err := db.Exec(query).Error; err != nil {
			return fmt.Errorf("failed to create enum type: %w", err)
		}
	}

	return nil
}

// createAdditionalIndexes creates additional indexes not covered by GORM tags
func (db *DB) createAdditionalIndexes() error {
	indexQueries := []string{
		`CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN (roles);`,
		`CREATE INDEX IF NOT EXISTS idx_social_accounts_provider_uid ON social_accounts (provider, provider_uid);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_time ON audit_logs (user_id, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_code_login_tokens_identifier_channel ON code_login_tokens (identifier, channel);`,
	}

	for _, query := range indexQueries {
		if err := db.Exec(query).Error; err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Health checks if the database is healthy
func (db *DB) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.PingContext(ctx)
}

// CleanupExpiredTokens removes expired tokens from various tables
func (db *DB) CleanupExpiredTokens() error {
	// Clean up expired JWT blacklist entries
	if err := db.Where("expires_at < ?", time.Now()).Delete(&models.JWTBlacklist{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup expired JWT blacklist: %w", err)
	}

	// Clean up expired password reset tokens
	if err := db.Where("expires_at < ?", time.Now()).Delete(&models.PasswordResetToken{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup expired password reset tokens: %w", err)
	}

	// Clean up expired code login tokens
	if err := db.Where("expires_at < ?", time.Now()).Delete(&models.CodeLoginToken{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup expired code login tokens: %w", err)
	}

	// Clean up expired login attempts
	if err := db.Where("locked_until IS NOT NULL AND locked_until < ?", time.Now()).
		Update("locked_until", nil).Error; err != nil {
		return fmt.Errorf("failed to cleanup expired login attempts: %w", err)
	}

	return nil
}

// Transaction runs a function within a database transaction
func (db *DB) Transaction(fn func(*gorm.DB) error) error {
	return db.DB.Transaction(fn)
}

// CreateTables is an alias for AutoMigrate for backward compatibility
func (db *DB) CreateTables() error {
	return db.AutoMigrate()
}
