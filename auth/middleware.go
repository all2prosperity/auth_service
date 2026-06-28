package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/all2prosperity/auth_service/services"
)

// JWTService exposes the module's JWT service so embedding services can reuse
// the exact same validation (signature + expiry + revocation/epoch) and token
// issuance, instead of re-implementing JWT parsing against a shared secret.
func (m *AuthModule) JWTService() *services.JWTService {
	return m.jwtService
}

// AuthMiddleware returns an HTTP middleware that validates the bearer access
// token on each request (including blacklist/epoch revocation), and injects the
// resulting claims into the request context. Requests without a valid token are
// rejected with 401 and a JSON body. Downstream handlers read the authenticated
// user via UserIDFromContext / services.ClaimsFromContext.
//
// This is the supported integration point for other modules (e.g. the economy
// service) that mount their own routes on the same router and need the same
// authentication as the auth endpoints.
func (m *AuthModule) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r.Header.Get("Authorization"))
			if token == "" {
				writeAuthError(w, "authentication required")
				return
			}
			claims, err := m.jwtService.ValidateAccessToken(token)
			if err != nil {
				writeAuthError(w, "invalid or expired token")
				return
			}
			ctx := services.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserIDFromContext returns the authenticated user's ULID from a context that
// passed through AuthMiddleware, or "" if the request was unauthenticated.
func UserIDFromContext(ctx context.Context) string {
	claims := services.ClaimsFromContext(ctx)
	if claims == nil {
		return ""
	}
	return claims.UserID
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(authHeader string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
}

func writeAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    "unauthenticated",
			"message": message,
		},
	})
}
