package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jwtconfig "github.com/kubestellar/ui/jwt"
)

// TokenClaims represents the JWT token claims
type TokenClaims struct {
	Username    string   `json:"username"`
	Permissions []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// RefreshTokenClaims represents the claims in a refresh token
type RefreshTokenClaims struct {
	Username    string   `json:"username"`
	Permissions []string `json:"permissions,omitempty"`
	TokenID     string   `json:"tokenId"`
	jwt.RegisteredClaims
}

// GenerateTokenPair creates a new JWT token and refresh token for a user
func GenerateTokenPair(username string, permissions []string) (string, string, error) {
	// Generate a random token ID for this session
	tokenID := fmt.Sprintf("%d", time.Now().UnixNano())
	
	// Get token expiration times
	accessExpTime := jwtconfig.GetTokenExpiration()
	refreshExpTime := jwtconfig.GetRefreshTokenExpiration()
	
	// Create access token claims
	accessClaims := TokenClaims{
		Username:    username,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessExpTime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "kubestellar-ui",
			ID:        tokenID,
		},
	}
	
	// Create refresh token claims
	refreshClaims := RefreshTokenClaims{
		Username:    username,
		Permissions: permissions,
		TokenID:     tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshExpTime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "kubestellar-ui",
		},
	}

	// Create tokens with claims
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	// Sign tokens
	accessTokenString, err := accessToken.SignedString([]byte(jwtconfig.GetJWTSecret()))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %v", err)
	}
	
	refreshTokenString, err := refreshToken.SignedString([]byte(jwtconfig.GetJWTSecret()))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %v", err)
	}

	return accessTokenString, refreshTokenString, nil
}

// GenerateToken creates a new JWT token for a user with specified permissions
// Maintained for backward compatibility
func GenerateToken(username string, permissions []string) (string, error) {
	token, _, err := GenerateTokenPair(username, permissions)
	return token, err
}

// ValidateToken validates a JWT token and returns the parsed claims
func ValidateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&TokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// Validate the alg is what we expect
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtconfig.GetJWTSecret()), nil
		},
	)

	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token and returns the parsed claims
func ValidateRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&RefreshTokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// Validate the alg is what we expect
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtconfig.GetJWTSecret()), nil
		},
	)

	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Extract claims
	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid refresh token claims")
	}

	return claims, nil
}
