package rest

import (
	"net"
	"net/http"
	"strings"

	"github.com/all2prosperity/auth_service/core"
	"github.com/all2prosperity/auth_service/services"
)

// requireAuth validates the bearer access token (including revocation checks)
// and injects the resulting claims into the request context. Requests without a
// valid token are rejected with 401.
func requireAuth(jwt *services.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r.Header.Get("Authorization"))
			if token == "" {
				writeError(w, &core.Error{Code: core.CodeUnauthenticated, Message: "authentication required"})
				return
			}
			claims, err := jwt.ValidateAccessToken(token)
			if err != nil {
				writeError(w, &core.Error{Code: core.CodeUnauthenticated, Message: "invalid token"})
				return
			}
			ctx := services.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(authHeader string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
}

// clientIP extracts the client IP, preferring the first X-Forwarded-For hop.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
