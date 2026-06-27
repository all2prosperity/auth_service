package dao_test

import (
	"testing"
	"time"

	"github.com/all2prosperity/auth_service/dao"
	"github.com/all2prosperity/auth_service/internal/testdb"
	"github.com/all2prosperity/auth_service/models"

	"github.com/oklog/ulid/v2"
)

func strptr(s string) *string { return &s }

func seedUser(t *testing.T, d *dao.UserDAO, email, phone string) *models.User {
	t.Helper()
	u := &models.User{
		Email:        strptr(email),
		PhoneNumber:  strptr(phone),
		PasswordHash: strptr("hash"),
		Roles:        []string{"user"},
	}
	if err := d.CreateUser(u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestUserDAO_LookupVariants(t *testing.T) {
	d := dao.NewUserDAO(testdb.New(t))
	u := seedUser(t, d, "lookup@example.com", "+8613800000001")

	if got, err := d.GetUserByID(u.ID); err != nil || got.ID != u.ID {
		t.Fatalf("GetUserByID: got=%v err=%v", got, err)
	}
	if got, err := d.GetUserByEmail("lookup@example.com"); err != nil || got.ID != u.ID {
		t.Fatalf("GetUserByEmail: got=%v err=%v", got, err)
	}
	if got, err := d.GetUserByPhoneNumber("+8613800000001"); err != nil || got.ID != u.ID {
		t.Fatalf("GetUserByPhoneNumber: got=%v err=%v", got, err)
	}
	if got, err := d.GetUserByIdentifier("lookup@example.com"); err != nil || got.ID != u.ID {
		t.Fatalf("GetUserByIdentifier(email): got=%v err=%v", got, err)
	}
	if got, err := d.GetUserByIdentifier("+8613800000001"); err != nil || got.ID != u.ID {
		t.Fatalf("GetUserByIdentifier(phone): got=%v err=%v", got, err)
	}
}

func TestUserDAO_NotFound(t *testing.T) {
	d := dao.NewUserDAO(testdb.New(t))
	if _, err := d.GetUserByEmail("missing@example.com"); err == nil {
		t.Fatal("expected error for missing user")
	}
}

func TestUserDAO_LockUnlock(t *testing.T) {
	d := dao.NewUserDAO(testdb.New(t))
	u := seedUser(t, d, "lock@example.com", "+8613800000002")
	id := ulid.MustParse(u.ID)

	until := time.Now().Add(time.Hour)
	if err := d.LockUser(id, until); err != nil {
		t.Fatalf("lock: %v", err)
	}
	got, _ := d.GetUserByID(u.ID)
	if !got.IsLocked() {
		t.Fatal("user should be locked")
	}

	if err := d.UnlockUser(id); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	got, _ = d.GetUserByID(u.ID)
	if got.IsLocked() {
		t.Fatal("user should be unlocked")
	}
}

func TestUserDAO_UpdatesAndConfirm(t *testing.T) {
	d := dao.NewUserDAO(testdb.New(t))
	u := seedUser(t, d, "upd@example.com", "+8613800000003")
	id := ulid.MustParse(u.ID)

	if err := d.UpdateUserPassword(id, "new-hash"); err != nil {
		t.Fatalf("update password: %v", err)
	}
	got, _ := d.GetUserByID(u.ID)
	if got.PasswordHash == nil || *got.PasswordHash != "new-hash" {
		t.Fatal("password hash not updated")
	}

	if err := d.UpdateUserRoles(id, []string{"admin", "user"}); err != nil {
		t.Fatalf("update roles: %v", err)
	}
	got, _ = d.GetUserByID(u.ID)
	if !got.HasRole("admin") {
		t.Fatalf("roles not updated, got %v", got.Roles)
	}

	if got.IsConfirmed() {
		t.Fatal("user should not be confirmed yet")
	}
	if err := d.ConfirmUser(id); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	got, _ = d.GetUserByID(u.ID)
	if !got.IsConfirmed() {
		t.Fatal("user should be confirmed")
	}
}
