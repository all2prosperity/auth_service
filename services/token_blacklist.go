package services

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
)

// TokenBlacklist provides server-side token revocation backed by Redis.
//
// It supports two revocation mechanisms:
//   - Per-token: a JTI is blacklisted until its natural expiry (used by logout
//     and refresh-token rotation).
//   - Per-user: an incrementing "epoch" invalidates every token issued before
//     the bump (used to revoke all of a user's sessions at once).
//
// All reads fail open: if Redis is unavailable, tokens are treated as valid so
// that an outage degrades availability rather than locking everyone out.
type TokenBlacklist struct {
	redis     *redis.Client
	epochTTL  time.Duration // how long to retain a user's epoch counter
	keyPrefix string
}

// NewTokenBlacklist creates a Redis-backed token blacklist. epochTTL should be
// at least the refresh-token lifetime so a revocation outlives every token it
// must invalidate.
func NewTokenBlacklist(client *redis.Client, epochTTL time.Duration) *TokenBlacklist {
	return &TokenBlacklist{
		redis:     client,
		epochTTL:  epochTTL,
		keyPrefix: "auth",
	}
}

func (b *TokenBlacklist) jtiKey(jti string) string {
	return fmt.Sprintf("%s:bl:jti:%s", b.keyPrefix, jti)
}

func (b *TokenBlacklist) epochKey(userID string) string {
	return fmt.Sprintf("%s:token_epoch:%s", b.keyPrefix, userID)
}

// Revoke blacklists a single token by its JTI until ttl elapses. A non-positive
// ttl is a no-op (the token has already expired).
func (b *TokenBlacklist) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	if b == nil || b.redis == nil || jti == "" || ttl <= 0 {
		return nil
	}
	if err := b.redis.Set(ctx, b.jtiKey(jti), "1", ttl).Err(); err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	return nil
}

// isJTIRevoked reports whether a specific JTI has been blacklisted. Fails open.
func (b *TokenBlacklist) isJTIRevoked(ctx context.Context, jti string) bool {
	if b == nil || b.redis == nil || jti == "" {
		return false
	}
	n, err := b.redis.Exists(ctx, b.jtiKey(jti)).Result()
	if err != nil {
		return false
	}
	return n > 0
}

// UserEpoch returns the current revocation epoch for a user (0 if never revoked).
func (b *TokenBlacklist) UserEpoch(ctx context.Context, userID string) int {
	if b == nil || b.redis == nil || userID == "" {
		return 0
	}
	val, err := b.redis.Get(ctx, b.epochKey(userID)).Result()
	if err != nil {
		return 0 // missing key or Redis error → epoch 0
	}
	epoch, err := strconv.Atoi(val)
	if err != nil {
		return 0
	}
	return epoch
}

// RevokeUser invalidates all tokens issued to a user by bumping their epoch.
// Returns the new epoch value.
func (b *TokenBlacklist) RevokeUser(ctx context.Context, userID string) (int, error) {
	if b == nil || b.redis == nil || userID == "" {
		return 0, fmt.Errorf("token blacklist is not available")
	}
	key := b.epochKey(userID)
	epoch, err := b.redis.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to revoke user tokens: %w", err)
	}
	// Refresh the retention window so the epoch outlives existing tokens.
	if b.epochTTL > 0 {
		_ = b.redis.Expire(ctx, key, b.epochTTL).Err()
	}
	return int(epoch), nil
}

// IsRevoked reports whether a token identified by (jti, userID, epoch) has been
// revoked, either individually or via a user-wide epoch bump. Fails open.
func (b *TokenBlacklist) IsRevoked(ctx context.Context, jti, userID string, tokenEpoch int) bool {
	if b == nil || b.redis == nil {
		return false
	}
	if b.isJTIRevoked(ctx, jti) {
		return true
	}
	return tokenEpoch < b.UserEpoch(ctx, userID)
}
