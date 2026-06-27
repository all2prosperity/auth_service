package testsupport_test

import (
	"testing"

	"github.com/all2prosperity/auth_service/internal/testsupport"
	"github.com/all2prosperity/auth_service/models"
)

// TestHarnessSmoke verifies the SQLite migration and core wiring stand up, and
// that a User row (with JSONSlice roles + ULID hook) round-trips.
func TestHarnessSmoke(t *testing.T) {
	deps := testsupport.NewCore(t)

	email := "smoke@example.com"
	u := &models.User{Email: &email}
	if err := testsupport.RawDB(deps.DB).Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	if u.ID == "" {
		t.Fatal("expected BeforeCreate to set a ULID id")
	}
	if len(u.Roles) == 0 || u.Roles[0] != "user" {
		t.Fatalf("expected default roles [user], got %v", u.Roles)
	}

	var got models.User
	if err := testsupport.RawDB(deps.DB).Where("email = ?", email).First(&got).Error; err != nil {
		t.Fatalf("read back user: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("roundtrip id mismatch: %s != %s", got.ID, u.ID)
	}
}
