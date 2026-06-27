// Package testdb provides an in-memory SQLite *database.DB for tests. It imports
// only database/models (never services/dao/core), so both white-box and
// black-box test packages can use it without import cycles.
package testdb

import (
	"testing"

	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// migratedModels mirrors database.AutoMigrate but skips the Postgres-only custom
// types and GIN/inet indexes that SQLite cannot create.
var migratedModels = []any{
	&models.User{},
	&models.SocialAccount{},
	&models.PasswordResetToken{},
	&models.CodeLoginToken{},
	&models.AuditLog{},
	&models.LoginAttempt{},
}

// New returns an in-memory SQLite database wrapped as *database.DB with all
// models migrated. The pool is pinned to one connection so the in-memory schema
// survives for the test's lifetime.
func New(t *testing.T) *database.DB {
	t.Helper()

	gormDB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	sqlDB, err := gormDB.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	if err := gormDB.AutoMigrate(migratedModels...); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	t.Cleanup(func() { _ = sqlDB.Close() })
	return database.NewDatabaseFromGORM(gormDB)
}

// Raw exposes the underlying *gorm.DB for direct row assertions.
func Raw(db *database.DB) *gorm.DB { return db.DB }
