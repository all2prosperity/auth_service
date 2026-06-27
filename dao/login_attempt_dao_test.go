package dao_test

import (
	"testing"
	"time"

	"github.com/all2prosperity/auth_service/dao"
	"github.com/all2prosperity/auth_service/internal/testdb"
)

func TestLoginAttemptDAO_RecordAndLock(t *testing.T) {
	d := dao.NewLoginAttemptDAO(testdb.New(t))
	const id, ip = "user@example.com", "1.2.3.4"
	const maxAttempts = 3
	lockFor := time.Hour

	// First failure creates the record.
	a, err := d.RecordFailure(id, ip, maxAttempts, lockFor)
	if err != nil {
		t.Fatalf("record 1: %v", err)
	}
	if a.Attempts != 1 || a.IsLocked() {
		t.Fatalf("after 1 failure: attempts=%d locked=%v", a.Attempts, a.IsLocked())
	}

	// Reach the threshold.
	_, _ = d.RecordFailure(id, ip, maxAttempts, lockFor)
	a, err = d.RecordFailure(id, ip, maxAttempts, lockFor)
	if err != nil {
		t.Fatalf("record 3: %v", err)
	}
	if a.Attempts != 3 || !a.IsLocked() {
		t.Fatalf("after 3 failures: attempts=%d locked=%v (want 3, locked)", a.Attempts, a.IsLocked())
	}

	// Get reflects the persisted lock.
	got, err := d.Get(id, ip)
	if err != nil || got == nil || !got.IsLocked() {
		t.Fatalf("Get after lock: got=%v err=%v", got, err)
	}
}

func TestLoginAttemptDAO_Reset(t *testing.T) {
	d := dao.NewLoginAttemptDAO(testdb.New(t))
	const id, ip = "user@example.com", "1.2.3.4"

	if _, err := d.RecordFailure(id, ip, 5, time.Hour); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := d.Reset(id, ip); err != nil {
		t.Fatalf("reset: %v", err)
	}

	got, err := d.Get(id, ip)
	if err != nil {
		t.Fatalf("get after reset: %v", err)
	}
	if got != nil {
		t.Fatalf("expected no record after reset, got %+v", got)
	}
}

func TestLoginAttemptDAO_GetMissing(t *testing.T) {
	d := dao.NewLoginAttemptDAO(testdb.New(t))
	got, err := d.Get("nobody@example.com", "9.9.9.9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing record, got %+v", got)
	}
}
