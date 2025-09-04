package services

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
)

/*
JWT Token Refresh Strategies:

1. Full Token Rotation (RefreshTokenPair):
   - Both access token and refresh token are regenerated
   - Old refresh token is blacklisted immediately
   - Highest security level
   - More database writes (blacklist operations)
   - Recommended for high-security applications

2. Access Token Only (RefreshAccessTokenOnly):
   - Only access token is regenerated
   - Refresh token remains the same
   - Lower security level (refresh token can be reused)
   - Fewer database writes
   - Suitable for performance-critical applications

3. Configurable Rotation (RefreshTokenPairWithRotation):
   - Allows choosing between the two strategies
   - Can implement hybrid approaches (e.g., rotate refresh token every N refreshes)
   - Provides flexibility based on security requirements

Security Considerations:
- Full rotation prevents refresh token reuse attacks
- Access-only refresh reduces database load but increases security risk
- Consider implementing refresh token reuse detection for access-only strategy
*/

// JWTClaims represents JWT claims
type JWTClaims struct {
	UserID string   `json:"user_id"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

// JWTService handles JWT operations
type JWTService struct {
	config *config.JWTConfig
	db     *database.DB
}

// NewJWTService creates a new JWT service
func NewJWTService(cfg *config.JWTConfig, db *database.DB) *JWTService {
	return &JWTService{
		config: cfg,
		db:     db,
	}
}

// GenerateTokenPair generates access and refresh tokens for a user
func (s *JWTService) GenerateTokenPair(user *models.User) (accessToken, refreshToken string, err error) {
	now := time.Now()
	jti := generateJTI()

	// Generate access token
	accessClaims := &JWTClaims{
		UserID: user.ID,
		Roles:  user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   user.ID,
			Issuer:    s.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenTTL)),
		},
	}

	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessTokenObj.SignedString([]byte(s.config.AccessSecret))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshJTI := generateJTI()
	refreshClaims := &JWTClaims{
		UserID: user.ID,
		Roles:  user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refreshJTI,
			Subject:   user.ID,
			Issuer:    s.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.RefreshTokenTTL)),
		},
	}

	refreshTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refreshTokenObj.SignedString([]byte(s.config.RefreshSecret))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// ValidateAccessToken validates an access token and returns claims
func (s *JWTService) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.AccessSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Check if token is blacklisted
	blacklisted, err := s.IsTokenBlacklisted(claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check blacklist: %w", err)
	}
	if blacklisted {
		return nil, fmt.Errorf("token is blacklisted")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token and returns claims
func (s *JWTService) ValidateRefreshToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.RefreshSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Check if token is blacklisted
	blacklisted, err := s.IsTokenBlacklisted(claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check blacklist: %w", err)
	}
	if blacklisted {
		return nil, fmt.Errorf("token is blacklisted")
	}

	return claims, nil
}

// BlacklistToken adds a token to the blacklist
func (s *JWTService) BlacklistToken(tokenID string, userID string, expiresAt time.Time) error {
	blacklistEntry := &models.JWTBlacklist{
		TokenID:   tokenID,
		UserID:    &userID, // TODO: fix this
		ExpiresAt: expiresAt,
	}

	result := s.db.Create(blacklistEntry)
	if result.Error != nil {
		return fmt.Errorf("failed to blacklist token: %w", result.Error)
	}

	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *JWTService) IsTokenBlacklisted(tokenID string) (bool, error) {
	var count int64
	res := s.db.Table("jwt_blacklist").Where("token_id = ? AND expires_at > now()", tokenID).Count(&count)
	if res.Error != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", res.Error)
	}

	return count > 0, nil
}

// BlacklistAllUserTokens blacklists all tokens for a user
func (s *JWTService) BlacklistAllUserTokens(userID string) error {
	// This would invalidate all tokens for the user
	// Implementation depends on how you want to handle this
	return nil
}

// RefreshTokenPair generates a new token pair using a refresh token
func (s *JWTService) RefreshTokenPair(refreshToken string, user *models.User) (string, string, error) {
	// Validate refresh token
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Verify the token belongs to the user
	if claims.UserID != user.ID {
		return "", "", fmt.Errorf("token does not belong to user")
	}

	// Blacklist the old refresh token
	err = s.BlacklistToken(claims.ID, user.ID, claims.ExpiresAt.Time.UTC())
	if err != nil {
		return "", "", fmt.Errorf("failed to blacklist old token: %w", err)
	}

	// Generate new token pair
	return s.GenerateTokenPair(user)
}

// RefreshAccessTokenOnly generates only a new access token using a refresh token
// This is a less secure approach but reduces database writes
func (s *JWTService) RefreshAccessTokenOnly(refreshToken string, user *models.User) (string, error) {
	// Validate refresh token
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Verify the token belongs to the user
	if claims.UserID != user.ID {
		return "", fmt.Errorf("token does not belong to user")
	}

	// Generate only access token (reuse refresh token)
	now := time.Now()
	jti := generateJTI()

	accessClaims := &JWTClaims{
		UserID: user.ID,
		Roles:  user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   user.ID,
			Issuer:    s.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenTTL)),
		},
	}

	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err := accessTokenObj.SignedString([]byte(s.config.AccessSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return accessToken, nil
}

// RefreshTokenPairWithRotation generates a new token pair with configurable rotation strategy
func (s *JWTService) RefreshTokenPairWithRotation(refreshToken string, user *models.User, rotateRefreshToken bool) (string, string, error) {
	// Validate refresh token
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Verify the token belongs to the user
	if claims.UserID != user.ID {
		return "", "", fmt.Errorf("token does not belong to user")
	}

	if rotateRefreshToken {
		// Blacklist the old refresh token for rotation
		err = s.BlacklistToken(claims.ID, user.ID, claims.ExpiresAt.Time.UTC())
		if err != nil {
			return "", "", fmt.Errorf("failed to blacklist old token: %w", err)
		}
		// Generate new token pair
		return s.GenerateTokenPair(user)
	} else {
		// Only generate new access token, keep the same refresh token
		accessToken, err := s.RefreshAccessTokenOnly(refreshToken, user)
		if err != nil {
			return "", "", err
		}
		return accessToken, refreshToken, nil
	}
}

// generateJTI generates a unique JWT ID
func generateJTI() string {
	// Generate a random 16-byte value
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to ULID if random generation fails
		return ulid.Make().String()
	}
	return fmt.Sprintf("%x", bytes)
}

// ExtractUserID extracts user ID from token string without validating signature
func (s *JWTService) ExtractUserID(tokenString string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	return claims.UserID, nil
}

// CleanupExpiredBlacklist removes expired tokens from blacklist
func (s *JWTService) CleanupExpiredBlacklist() error {
	query := `DELETE FROM jwt_blacklist WHERE expires_at < now()`
	res := s.db.Exec(query)
	if res.Error != nil {
		return fmt.Errorf("failed to cleanup expired blacklist: %w", res.Error)
	}
	return nil
}
