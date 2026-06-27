package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/all2prosperity/auth_service/internal/testsupport"
	"github.com/all2prosperity/auth_service/services"
)

func TestTokenBlacklist_RevokeJTI(t *testing.T) {
	rdb := testsupport.NewRedis(t)
	bl := services.NewTokenBlacklist(rdb, time.Hour)
	ctx := context.Background()

	if bl.IsRevoked(ctx, "jti-1", "user-1", 0) {
		t.Fatal("fresh jti should not be revoked")
	}
	if err := bl.Revoke(ctx, "jti-1", time.Hour); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !bl.IsRevoked(ctx, "jti-1", "user-1", 0) {
		t.Fatal("revoked jti should be reported revoked")
	}
	// A different jti for the same user is unaffected.
	if bl.IsRevoked(ctx, "jti-2", "user-1", 0) {
		t.Fatal("unrelated jti should not be revoked")
	}
}

func TestTokenBlacklist_RevokeUserEpoch(t *testing.T) {
	rdb := testsupport.NewRedis(t)
	bl := services.NewTokenBlacklist(rdb, time.Hour)
	ctx := context.Background()

	if got := bl.UserEpoch(ctx, "user-1"); got != 0 {
		t.Fatalf("initial epoch = %d, want 0", got)
	}

	epoch, err := bl.RevokeUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("revoke user: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("epoch after revoke = %d, want 1", epoch)
	}

	// A token issued at epoch 0 is now revoked; one issued at epoch 1 is valid.
	if !bl.IsRevoked(ctx, "jti-x", "user-1", 0) {
		t.Fatal("token from epoch 0 should be revoked after user revoke")
	}
	if bl.IsRevoked(ctx, "jti-x", "user-1", 1) {
		t.Fatal("token from current epoch should not be revoked")
	}
	// Other users unaffected.
	if bl.IsRevoked(ctx, "jti-y", "user-2", 0) {
		t.Fatal("other user should not be affected by user-1 revoke")
	}
}

func TestTokenBlacklist_FailOpenWhenRedisDown(t *testing.T) {
	rdb := testsupport.NewRedis(t)
	bl := services.NewTokenBlacklist(rdb, time.Hour)
	ctx := context.Background()

	// Close the client to simulate Redis being unavailable.
	_ = rdb.Close()

	// Reads must fail open (treat as not revoked) so an outage doesn't lock
	// everyone out.
	if bl.IsRevoked(ctx, "jti-1", "user-1", 0) {
		t.Fatal("IsRevoked should fail open when Redis is unavailable")
	}
}
