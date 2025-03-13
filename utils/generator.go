package utils

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/VanitasCaesar1/backend/cache"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

// IDGenerator manages the generation of unique 8-character alphanumeric IDs
type IDGenerator struct {
	// Track recently generated IDs to ensure uniqueness
	usedIDs      map[string]bool
	mutex        sync.Mutex
	characterSet []rune
}

// NewIDGenerator creates a new instance of IDGenerator
func NewIDGenerator() *IDGenerator {
	// Use only capital letters and numbers for better legibility
	// Omitting easily confused characters: 0, O, 1, I
	characterSet := []rune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

	return &IDGenerator{
		usedIDs:      make(map[string]bool),
		characterSet: characterSet,
	}
}

// GenerateID creates a new unique 8-character ID
func (g *IDGenerator) GenerateID() (string, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	// Seed with current time to add entropy

	// Maximum attempts to avoid infinite loops
	maxAttempts := 100
	attempts := 0

	for attempts < maxAttempts {
		attempts++

		// Generate ID
		id, err := g.generateRandomID(8)
		if err != nil {
			return "", err
		}

		// Check if ID is already used
		if !g.usedIDs[id] {
			g.usedIDs[id] = true
			return id, nil
		}
	}

	return "", fmt.Errorf("failed to generate unique ID after %d attempts", maxAttempts)
}

// generateRandomID creates a random ID of specified length
func (g *IDGenerator) generateRandomID(length int) (string, error) {
	result := make([]rune, length)

	// Get character set length
	charSetLength := big.NewInt(int64(len(g.characterSet)))

	for i := 0; i < length; i++ {
		// Generate cryptographically secure random number
		randomIndex, err := rand.Int(rand.Reader, charSetLength)
		if err != nil {
			return "", err
		}

		// Select character from set
		result[i] = g.characterSet[randomIndex.Int64()]
	}

	return string(result), nil
}

// CleanupOldIDs removes old IDs to prevent memory leaks when using long-term
// Only use this if your application runs for extended periods
func (g *IDGenerator) CleanupOldIDs(maxSize int) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	// If the used IDs map gets too large, reset it
	// In a production system, you'd want to store IDs in a database
	if len(g.usedIDs) > maxSize {
		g.usedIDs = make(map[string]bool)
	}
}

// JwtTokenGenerator manages the generation of unique tokens
type JwtTokenGenerator struct {
	// Track recently generated IDs to ensure uniqueness
	usedTokens map[string]bool
	mutex      sync.Mutex
	cache      *cache.Cache
	secretKey  []byte
}

// NewJwtTokenGenerator creates a new JwtTokenGenerator
func NewJwtTokenGenerator(redisClient *redis.Client, secretKey string) *JwtTokenGenerator {
	return &JwtTokenGenerator{
		usedTokens: make(map[string]bool),
		cache:      cache.NewCache(redisClient, "jwt:"),
		secretKey:  []byte(secretKey),
	}
}

// generateJWT creates a JWT token for the given authentication ID
func (g *JwtTokenGenerator) GenerateJWT(ctx context.Context, authID uuid.UUID) (string, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	// Generate unique token identifier
	jti := uuid.New().String()

	// Ensure token uniqueness
	for g.usedTokens[jti] {
		jti = uuid.New().String()
	}
	g.usedTokens[jti] = true

	// Create the claims for the JWT
	claims := jwt.MapClaims{
		"sub":       authID.String(),                       // Subject (user ID)
		"auth_time": time.Now().Unix(),                     // Time of authentication
		"exp":       time.Now().Add(time.Hour * 24).Unix(), // Expiration (24 hours from now)
		"iat":       time.Now().Unix(),                     // Issued at
		"jti":       jti,                                   // Unique token identifier
	}

	// Create a new token with HS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token
	signedToken, err := token.SignedString(g.secretKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to sign token")
	}

	// Cache the token with expiration
	err = g.cache.Set(ctx, jti, claims, 24*time.Hour)
	if err != nil {
		return "", errors.Wrap(err, "failed to cache token")
	}

	return signedToken, nil
}

// verifyJWT verifies and parses the JWT token
func (g *JwtTokenGenerator) VerifyJWT(ctx context.Context, tokenString string) (*jwt.Token, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return g.secretKey, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to parse token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Verify token in cache
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, errors.New("invalid token identifier")
	}

	var cachedClaims jwt.MapClaims
	err = g.cache.Get(ctx, jti, &cachedClaims)
	if err != nil {
		return nil, errors.Wrap(err, "token not found in cache")
	}

	return token, nil
}

// InvalidateToken removes a token from the cache and used tokens
func (g *JwtTokenGenerator) InvalidateToken(ctx context.Context, jti string) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	delete(g.usedTokens, jti)
	return g.cache.Delete(ctx, jti)
}

// Optional: Token verification function
func verifyJWT(tokenString string) (*jwt.Token, error) {
	secretKey := []byte("your-secret-key-here") // Use the same secret key as in generation

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}
