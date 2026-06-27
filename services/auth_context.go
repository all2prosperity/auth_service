package services

import "context"

type contextKey string

const claimsContextKey contextKey = "auth.claims"

// WithClaims returns a copy of ctx carrying the authenticated JWT claims.
func WithClaims(ctx context.Context, claims *JWTClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext returns the authenticated JWT claims injected by the auth
// interceptor, or nil if the request was unauthenticated.
func ClaimsFromContext(ctx context.Context) *JWTClaims {
	claims, _ := ctx.Value(claimsContextKey).(*JWTClaims)
	return claims
}
