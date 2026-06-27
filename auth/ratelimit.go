package auth

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// IPRateLimitMiddleware returns a chi/HTTP middleware that limits requests per
// client IP using a Redis fixed-window counter. It is a no-op when rate limiting
// is disabled (IPRateLimit <= 0) or Redis is unavailable (fails open).
func (m *AuthModule) IPRateLimitMiddleware() func(http.Handler) http.Handler {
	limit := m.config.Security.IPRateLimit
	window := m.config.Security.IPRateWindow
	if window <= 0 {
		window = time.Minute
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limit <= 0 || m.redisClient == nil {
				next.ServeHTTP(w, r)
				return
			}

			ip := requestIP(r)
			bucket := time.Now().Unix() / int64(window.Seconds())
			key := fmt.Sprintf("auth:ratelimit:%s:%d", ip, bucket)

			ctx := r.Context()
			count, err := m.redisClient.Incr(ctx, key).Result()
			if err != nil {
				// Fail open: do not block traffic when Redis is down.
				next.ServeHTTP(w, r)
				return
			}
			if count == 1 {
				_ = m.redisClient.Expire(ctx, key, window).Err()
			}
			if count > int64(limit) {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// requestIP extracts the client IP, preferring the first X-Forwarded-For hop.
func requestIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
