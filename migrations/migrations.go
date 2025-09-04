package migrations

import (
	"fmt"
	"time"

	"github.com/all2prosperity/auth_service/models"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// MigrationManager handles database migrations
type MigrationManager struct {
	db *gorm.DB
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *gorm.DB) *MigrationManager {
	return &MigrationManager{db: db}
}

// RunMigrations runs all necessary migrations
func (m *MigrationManager) RunMigrations() error {
	// Create extensions
	if err := m.createExtensions(); err != nil {
		return fmt.Errorf("failed to create extensions: %w", err)
	}

	// Create custom types
	if err := m.createCustomTypes(); err != nil {
		return fmt.Errorf("failed to create custom types: %w", err)
	}

	// Auto migrate all models
	err := m.db.AutoMigrate(
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
	if err := m.createAdditionalIndexes(); err != nil {
		return fmt.Errorf("failed to create additional indexes: %w", err)
	}

	// Create triggers
	if err := m.createTriggers(); err != nil {
		return fmt.Errorf("failed to create triggers: %w", err)
	}

	return nil
}

// createExtensions creates necessary PostgreSQL extensions
func (m *MigrationManager) createExtensions() error {
	extensions := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`,
	}

	for _, ext := range extensions {
		if err := m.db.Exec(ext).Error; err != nil {
			return fmt.Errorf("failed to create extension: %w", err)
		}
	}

	return nil
}

// createCustomTypes creates custom PostgreSQL types
func (m *MigrationManager) createCustomTypes() error {
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
		if err := m.db.Exec(query).Error; err != nil {
			return fmt.Errorf("failed to create enum type: %w", err)
		}
	}

	return nil
}

// createAdditionalIndexes creates additional indexes not covered by GORM tags
func (m *MigrationManager) createAdditionalIndexes() error {
	indexQueries := []string{
		`CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN (roles);`,
		`CREATE INDEX IF NOT EXISTS idx_social_accounts_provider_uid ON social_accounts (provider, provider_uid);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_time ON audit_logs (user_id, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_code_login_tokens_identifier_channel ON code_login_tokens (identifier, channel);`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_locked ON login_attempts (locked_until);`,
	}

	for _, query := range indexQueries {
		if err := m.db.Exec(query).Error; err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// createTriggers creates database triggers
func (m *MigrationManager) createTriggers() error {
	triggerQueries := []string{
		// Auto-update timestamp trigger function
		`CREATE OR REPLACE FUNCTION trg_set_updated_at() RETURNS trigger AS $$
		BEGIN NEW.updated_at = now(); RETURN NEW; END;
		$$ LANGUAGE plpgsql;`,

		// Users table trigger
		`DROP TRIGGER IF EXISTS set_users_updated_at ON users;`,
		`CREATE TRIGGER set_users_updated_at
		BEFORE UPDATE ON users
		FOR EACH ROW EXECUTE PROCEDURE trg_set_updated_at();`,
	}

	for _, query := range triggerQueries {
		if err := m.db.Exec(query).Error; err != nil {
			return fmt.Errorf("failed to create trigger: %w", err)
		}
	}

	return nil
}

// RollbackMigrations rolls back migrations (for development/testing)
func (m *MigrationManager) RollbackMigrations() error {
	// Drop tables in reverse order
	tables := []string{
		"audit_logs",
		"login_attempts",
		"code_login_tokens",
		"password_reset_tokens",
		"jwt_blacklist",
		"social_accounts",
		"users",
	}

	for _, table := range tables {
		if err := m.db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE;", table)).Error; err != nil {
			return fmt.Errorf("failed to drop table %s: %w", table, err)
		}
	}

	// Drop custom types
	typeDrops := []string{
		"DROP TYPE IF EXISTS audit_action CASCADE;",
		"DROP TYPE IF EXISTS code_channel CASCADE;",
	}

	for _, query := range typeDrops {
		if err := m.db.Exec(query).Error; err != nil {
			return fmt.Errorf("failed to drop type: %w", err)
		}
	}

	return nil
}

// SeedData seeds initial data for development/testing
func (m *MigrationManager) SeedData() error {
	// Check if admin user already exists
	var count int64
	m.db.Model(&models.User{}).Where("'admin' = ANY(roles)").Count(&count)
	if count > 0 {
		return nil // Admin user already exists
	}

	// Create admin user
	adminUser := &models.User{
		Email:       stringPtr("admin@example.com"),
		Roles:       datatypes.JSONSlice[string]{"admin", "user"},
		ConfirmedAt: timePtr(time.Now()),
	}

	if err := m.db.Create(adminUser).Error; err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	return nil
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// CheckHealth checks if the database schema is up to date
func (m *MigrationManager) CheckHealth() error {
	// Simple check: ensure all tables exist
	tables := []string{"users", "social_accounts", "jwt_blacklist", "password_reset_tokens", "code_login_tokens", "audit_logs", "login_attempts"}

	for _, table := range tables {
		var exists bool
		err := m.db.Raw("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = ?)", table).Scan(&exists).Error
		if err != nil {
			return fmt.Errorf("failed to check table %s: %w", table, err)
		}
		if !exists {
			return fmt.Errorf("table %s does not exist", table)
		}
	}

	return nil
}
