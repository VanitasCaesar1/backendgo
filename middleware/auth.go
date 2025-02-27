package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5" // Add this import
	"github.com/redis/go-redis/v9"
	"github.com/workos-inc/workos-go/pkg/sso"
	"go.uber.org/zap"
)

// ClientType defines the type of client accessing the API
type ClientType string

const (
	WebApp       ClientType = "webapp"
	MobileApp    ClientType = "mobile"
	AdminPanel   ClientType = "admin"
	UserClient   ClientType = "user"
	DoctorClient ClientType = "doctor"
)

// SessionData stores the authenticated session information
type SessionData struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	UserID       string     `json:"user_id"`
	Email        string     `json:"email"`
	ClientType   ClientType `json:"client_type"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AuthMiddleware handles authentication for various client types
type AuthMiddleware struct {
	logger         *zap.Logger
	redis          *redis.Client
	workosClient   *sso.Client
	clientTypes    map[string]string     // Maps client ID to client type
	cookieNames    map[ClientType]string // Maps client type to cookie name
	config         *config.Config
	jwksCache      *sync.Map    // Cache for JWKS keys
	jwksCacheMutex sync.RWMutex // Mutex for cache operations
}

type AuthMiddlewareConfig struct {
	Logger       *zap.Logger
	Redis        *redis.Client
	workosClient *sso.Client
	ClientTypes  map[string]string
	CookieNames  map[ClientType]string
	Config       *config.Config
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config AuthMiddlewareConfig) *AuthMiddleware {
	// Set default cookie names if not provided
	if config.CookieNames == nil {
		config.CookieNames = map[ClientType]string{
			WebApp:       "hospital_web_session",
			MobileApp:    "doctor_web_session",
			UserClient:   "user_mobile_session",
			DoctorClient: "doctor_mobile_session",
		}
	}

	return &AuthMiddleware{
		logger:       config.Logger,
		redis:        config.Redis,
		workosClient: config.workosClient,
		clientTypes:  config.ClientTypes,
		cookieNames:  config.CookieNames,
		config:       config.Config,
		jwksCache:    &sync.Map{},
	}
}

// determineClientType identifies the client type from request headers
func (m *AuthMiddleware) determineClientType(c *fiber.Ctx) ClientType {
	// Check client ID from header
	clientID := c.Get("X-Client-ID")
	if clientID != "" {
		if clientType, exists := m.clientTypes[clientID]; exists {
			return ClientType(clientType)
		}
	}

	// Check User-Agent as fallback
	userAgent := c.Get("User-Agent")
	if strings.Contains(strings.ToLower(userAgent), "mobile") {
		return MobileApp
	}

	// Default to web app
	return WebApp
}

// Handler returns a middleware function that handles authentication
func (m *AuthMiddleware) Handler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Determine client type
		clientType := m.determineClientType(c)

		// Get appropriate cookie name
		cookieName := m.cookieNames[clientType]
		if cookieName == "" {
			cookieName = "session" // Fallback
		}

		// Attempt to get session ID
		var sessionID string

		// Try Authorization header first
		auth := c.Get("Authorization")
		if auth != "" && strings.HasPrefix(auth, "Bearer ") {
			sessionID = strings.TrimPrefix(auth, "Bearer ")
		}

		// Fall back to cookie
		if sessionID == "" {
			sessionID = c.Cookies(cookieName)
		}

		if sessionID == "" {
			m.logger.Debug("no authentication found",
				zap.String("path", c.Path()),
				zap.String("clientType", string(clientType)))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication required",
				"code":  "NO_SESSION",
			})
		}

		// Get session from Redis
		sessionKey := fmt.Sprintf("%s_session:%s", clientType, sessionID)
		sessionData, err := m.validateSession(c.Context(), sessionKey)
		if err != nil {
			m.logger.Debug("invalid session",
				zap.String("path", c.Path()),
				zap.Error(err))

			// Clear invalid cookie
			c.Cookie(&fiber.Cookie{
				Name:     cookieName,
				Value:    "",
				Expires:  time.Now().Add(-1 * time.Hour),
				HTTPOnly: true,
				Secure:   true,
				SameSite: "Lax",
				Path:     "/",
			})

			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired session",
				"code":  "SESSION_INVALID",
			})
		}

		// Store session data in context
		c.Locals("userID", sessionData.UserID)
		c.Locals("email", sessionData.Email)
		c.Locals("sessionID", sessionID)
		c.Locals("clientType", string(clientType))

		return c.Next()
	}
}

// Update the fetchJWKS method
// Update your fetchJWKS method for v2
func (m *AuthMiddleware) fetchJWKS() (*keyfunc.JWKS, error) {
	m.jwksCacheMutex.RLock()
	cachedJWKS, found := m.jwksCache.Load("jwks")
	m.jwksCacheMutex.RUnlock()

	if found {
		return cachedJWKS.(*keyfunc.JWKS), nil
	}

	// JWKS not in cache, fetch it
	m.jwksCacheMutex.Lock()
	defer m.jwksCacheMutex.Unlock()

	// Check again in case another goroutine updated while we were waiting
	if cachedJWKS, found := m.jwksCache.Load("jwks"); found {
		return cachedJWKS.(*keyfunc.JWKS), nil
	}

	// Get the JWKS from the remote server
	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			m.logger.Error("Failed to refresh JWKS", zap.Error(err))
		},
	}

	jwks, err := keyfunc.Get(m.config.WorkOSJWKSURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Cache the JWKS
	m.jwksCache.Store("jwks", jwks)

	return jwks, nil
}

// And update verifyJWT to use v5 syntax
func (m *AuthMiddleware) verifyJWT(tokenString string) error {
	jwks, err := m.fetchJWKS()
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	token, err := jwt.Parse(tokenString, jwks.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(m.config.ExpectedIssuer),
		jwt.WithAudience(m.config.ExpectedAudience))

	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

// validateSession validates a session from Redis and verifies the JWT token
func (m *AuthMiddleware) validateSession(ctx context.Context, sessionKey string) (*SessionData, error) {
	// Get session from Redis
	sessionBytes, err := m.redis.Get(ctx, sessionKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var sessionData SessionData
	if err := json.Unmarshal(sessionBytes, &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check if session has expired
	if time.Now().After(sessionData.ExpiresAt) {
		m.redis.Del(ctx, sessionKey)
		return nil, fmt.Errorf("session expired")
	}

	// Verify the JWT token
	if err := m.verifyJWT(sessionData.AccessToken); err != nil {
		m.logger.Error("JWT verification failed", zap.Error(err))
		m.redis.Del(ctx, sessionKey)
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	return &sessionData, nil
}

// CreateSession creates a new session in Redis
func (m *AuthMiddleware) CreateSession(ctx context.Context, userID, email, accessToken, refreshToken string, clientType ClientType, expiresIn time.Duration) (string, error) {
	// Generate a unique session ID
	sessionID := generateSessionID() // Implement this function

	// Create session data
	sessionData := SessionData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
		Email:        email,
		ClientType:   clientType,
		ExpiresAt:    time.Now().Add(expiresIn),
		CreatedAt:    time.Now(),
	}

	// Marshal session data to JSON
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Store session in Redis
	sessionKey := fmt.Sprintf("%s_session:%s", clientType, sessionID)
	if err := m.redis.Set(ctx, sessionKey, sessionBytes, expiresIn).Err(); err != nil {
		return "", fmt.Errorf("failed to store session: %w", err)
	}

	return sessionID, nil
}

// generateSessionID generates a secure random session ID
func generateSessionID() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		// Handle error appropriately in production
		return fmt.Sprintf("sess_%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// GetCookieName returns the cookie name for a client type
func (m *AuthMiddleware) GetCookieName(clientType ClientType) string {
	return m.cookieNames[clientType]
}
