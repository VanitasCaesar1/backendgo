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
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/sso"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
	"go.uber.org/zap"
)

// SessionData stores the authenticated session information
type SessionData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// AuthMiddleware handles authentication
type AuthMiddleware struct {
	logger         *zap.Logger
	redis          *redis.Client
	workosClient   *sso.Client
	cookieName     string
	config         *config.Config
	jwksCache      *sync.Map
	jwksCacheMutex sync.RWMutex
	jwksURL        string
}

type AuthMiddlewareConfig struct {
	Logger       *zap.Logger
	Redis        *redis.Client
	WorkosClient *sso.Client
	CookieName   string
	Config       *config.Config
	ClientID     string
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config AuthMiddlewareConfig) (*AuthMiddleware, error) {
	// Set default cookie name if not provided
	if config.CookieName == "" {
		config.CookieName = "session"
	}

	// Initialize the middleware
	middleware := &AuthMiddleware{
		logger:       config.Logger,
		redis:        config.Redis,
		workosClient: config.WorkosClient,
		cookieName:   config.CookieName,
		config:       config.Config,
		jwksCache:    &sync.Map{},
	}

	// Fetch JWKS URL from WorkOS using the client ID
	if config.ClientID != "" {
		jwksURLObj, err := usermanagement.GetJWKSURL(config.ClientID)
		if err != nil {
			return nil, fmt.Errorf("failed to get JWKS URL: %w", err)
		}
		middleware.jwksURL = jwksURLObj.String() // Convert *url.URL to string
		middleware.logger.Debug("Retrieved JWKS URL", zap.String("url", middleware.jwksURL))
	} else if config.Config.WorkOSJWKSURL != "" {
		// Use JWKS URL from config if client ID is not provided
		middleware.jwksURL = config.Config.WorkOSJWKSURL
		middleware.logger.Debug("Using JWKS URL from config", zap.String("url", middleware.jwksURL))
	} else {
		return nil, fmt.Errorf("either ClientID or WorkOSJWKSURL must be provided")
	}

	// Pre-fetch and cache JWKS
	_, err := middleware.fetchJWKS()
	if err != nil {
		middleware.logger.Warn("Failed to pre-fetch JWKS, will retry on demand", zap.Error(err))
	}

	return middleware, nil
}

// Handler returns a middleware function that handles authentication
func (m *AuthMiddleware) Handler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Attempt to get token from multiple sources
		var token string

		// Check all possible sources for the token
		// 1. Standard Authorization header
		auth := c.Get("Authorization")
		if auth != "" && strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
			m.logger.Debug("found token in Authorization header")
		}

		// 2. X-Authorization header (some clients use this)
		if token == "" {
			xAuth := c.Get("X-Authorization")
			if xAuth != "" {
				if strings.HasPrefix(xAuth, "Bearer ") {
					token = strings.TrimPrefix(xAuth, "Bearer ")
				} else {
					token = xAuth
				}
				m.logger.Debug("found token in X-Authorization header")
			}
		}

		// 3. WorkOS AuthKit specific header
		if token == "" {
			workosAuth := c.Get("X-WorkOS-Token")
			if workosAuth != "" {
				token = workosAuth
				m.logger.Debug("found token in X-WorkOS-Token header")
			}
		}

		// 4. Check for cookie
		if token == "" {
			cookieToken := c.Cookies(m.cookieName)
			if cookieToken != "" {
				token = cookieToken
				m.logger.Debug("found token in cookie",
					zap.String("cookieName", m.cookieName))
			}
		}

		// 5. Check for query parameter (not recommended for production but useful for debugging)
		if token == "" && c.Query("token") != "" {
			token = c.Query("token")
			m.logger.Debug("found token in query parameter")
		}

		// 6. Look for token in request body for POST requests
		if token == "" && c.Method() == "POST" {
			var body map[string]interface{}
			if err := c.BodyParser(&body); err == nil {
				if tokenVal, ok := body["token"].(string); ok && tokenVal != "" {
					token = tokenVal
					m.logger.Debug("found token in request body")
				}
			}
		}

		// Enhanced debug logging
		tokenParts := strings.Split(token, ".")
		m.logger.Debug("authentication attempt",
			zap.String("path", c.Path()),
			zap.Bool("token_found", token != ""),
			zap.Int("token_parts", len(tokenParts)))

		// No token found
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication failed: no token provided",
				"code":  "AUTH_FAILED",
			})
		}

		// Check if token is a JWT
		if strings.Contains(token, ".") && len(strings.Split(token, ".")) == 3 {
			// Verify JWT directly
			parsedToken, claims, err := m.verifyAndParseJWT(token)
			if err == nil && parsedToken.Valid {
				// JWT is valid, extract and set claims in context
				m.logger.Debug("JWT verification successful",
					zap.String("path", c.Path()))

				// Store the authentication ID (subject) from the JWT
				if sub, ok := claims["sub"].(string); ok {
					c.Locals("authID", sub)
					c.Locals("userID", sub) // Also set as userID for compatibility
					m.logger.Debug("set userID from token sub claim", zap.String("userID", sub))
				}

				// Also store email from act.sub if available
				if act, ok := claims["act"].(map[string]interface{}); ok {
					if email, ok := act["sub"].(string); ok {
						c.Locals("email", email)
						m.logger.Debug("set email from token act.sub claim", zap.String("email", email))
					}
				}

				// Store the full claims object for reference
				c.Locals("claims", claims)

				// Store the raw token for potential use in subsequent API calls
				c.Locals("token", token)

				return c.Next()
			} else {
				m.logger.Debug("direct JWT verification failed",
					zap.Error(err),
					zap.String("token_start", token[:min(len(token), 20)]))
			}
		}

		// If JWT verification failed or it wasn't a JWT, try Redis session
		sessionKey := fmt.Sprintf("session:%s", token)
		sessionData, err := m.validateSession(c.Context(), sessionKey)
		if err != nil {
			m.logger.Debug("invalid session",
				zap.String("path", c.Path()),
				zap.Error(err))
			// Clear invalid cookie if it came from a cookie
			if c.Cookies(m.cookieName) != "" {
				c.Cookie(&fiber.Cookie{
					Name:     m.cookieName,
					Value:    "",
					Expires:  time.Now().Add(-1 * time.Hour),
					HTTPOnly: true,
					Secure:   true,
					SameSite: "Lax",
					Path:     "/",
				})
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication failed: invalid token",
				"code":  "AUTH_FAILED",
			})
		}

		// If we have a session, verify its access token
		_, claims, err := m.verifyAndParseJWT(sessionData.AccessToken)
		if err != nil {
			m.logger.Error("Failed to parse session access token", zap.Error(err))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid access token in session",
				"code":  "AUTH_FAILED",
			})
		}

		// Store the authentication ID (subject) from the JWT
		if sub, ok := claims["sub"].(string); ok {
			c.Locals("authID", sub)
			c.Locals("userID", sub)
			m.logger.Debug("set userID from session token", zap.String("userID", sub))
		}
		// Also store the full claims object for reference
		c.Locals("claims", claims)

		// Store session data in context
		c.Locals("userID", sessionData.UserID)
		c.Locals("email", sessionData.Email)
		c.Locals("sessionID", token)
		c.Locals("token", sessionData.AccessToken) // Store the access token for use in downstream calls

		// Log successful session verification
		m.logger.Debug("session verification successful",
			zap.String("path", c.Path()),
			zap.String("userID", sessionData.UserID))

		return c.Next()
	}
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// fetchJWKS retrieves the JSON Web Key Set from the configured URL
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
		RefreshInterval: time.Hour, // Refresh keys every hour
	}

	m.logger.Debug("Fetching JWKS from URL", zap.String("url", m.jwksURL))
	jwks, err := keyfunc.Get(m.jwksURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Cache the JWKS
	m.jwksCache.Store("jwks", jwks)
	m.logger.Debug("Successfully cached JWKS")
	return jwks, nil
}

// verifyAndParseJWT verifies a JWT token and returns the parsed token and claims
func (m *AuthMiddleware) verifyAndParseJWT(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	jwks, err := m.fetchJWKS()
	if err != nil {
		m.logger.Error("Failed to fetch JWKS for JWT verification", zap.Error(err))
		return nil, nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Log token verification attempts with more details
	m.logger.Debug("Verifying JWT",
		zap.String("issuer", m.config.ExpectedIssuer),
		zap.String("token_prefix", tokenString[:min(20, len(tokenString))]))

	var claims jwt.MapClaims

	// Create parser options - only include necessary validations
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
	}

	// Only add issuer validation if ExpectedIssuer is configured
	if m.config.ExpectedIssuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(m.config.ExpectedIssuer))
	}

	// Only add audience validation if ExpectedAudience is configured
	// Based on the WorkOS docs, this doesn't appear to be a standard claim
	//if m.config.ExpectedAudience != "" {
	//	parserOptions = append(parserOptions, jwt.WithAudience(m.config.ExpectedAudience))
	//}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		jwks.Keyfunc,
		parserOptions...,
	)

	if err != nil {
		// Log detailed error info
		m.logger.Error("JWT validation failed",
			zap.Error(err),
			zap.String("token_start", tokenString[:min(len(tokenString), 20)]))
		return nil, nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		m.logger.Error("Token marked as invalid")
		return nil, nil, fmt.Errorf("invalid token")
	}

	// Verify required claims according to WorkOS docs
	if claims["sub"] == nil {
		m.logger.Error("JWT missing required 'sub' claim")
		return nil, nil, fmt.Errorf("token missing required 'sub' claim")
	}

	if claims["exp"] == nil {
		m.logger.Error("JWT missing required 'exp' claim")
		return nil, nil, fmt.Errorf("token missing required 'exp' claim")
	}

	// Log successful verification
	m.logger.Debug("JWT verification successful")

	// Log the claims for debugging
	claimsBytes, _ := json.Marshal(claims)
	m.logger.Debug("JWT claims", zap.String("claims", string(claimsBytes)))

	return token, claims, nil
}

// validateSession validates a session from Redis and verifies the JWT token
func (m *AuthMiddleware) validateSession(ctx context.Context, sessionKey string) (*SessionData, error) {
	// Get session from Redis
	m.logger.Debug("Validating session", zap.String("sessionKey", sessionKey))
	sessionBytes, err := m.redis.Get(ctx, sessionKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			m.logger.Debug("Session not found in Redis", zap.String("sessionKey", sessionKey))
			return nil, fmt.Errorf("session not found")
		}
		m.logger.Error("Failed to get session from Redis", zap.Error(err))
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var sessionData SessionData
	if err := json.Unmarshal(sessionBytes, &sessionData); err != nil {
		m.logger.Error("Failed to unmarshal session data", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check if session has expired
	if time.Now().After(sessionData.ExpiresAt) {
		m.logger.Debug("Session expired",
			zap.Time("expires_at", sessionData.ExpiresAt),
			zap.Time("now", time.Now()))
		m.redis.Del(ctx, sessionKey)
		return nil, fmt.Errorf("session expired")
	}

	// Only verify the JWT token if it has the structure of a JWT
	if strings.Contains(sessionData.AccessToken, ".") && len(strings.Split(sessionData.AccessToken, ".")) == 3 {
		// Verify the JWT token
		_, _, err := m.verifyAndParseJWT(sessionData.AccessToken)
		if err != nil {
			m.logger.Error("JWT verification failed for session token", zap.Error(err))
			m.redis.Del(ctx, sessionKey)
			return nil, fmt.Errorf("invalid access token: %w", err)
		}
	} else {
		m.logger.Debug("Access token in session is not a standard JWT, skipping verification")
	}

	m.logger.Debug("Session validation successful",
		zap.String("userID", sessionData.UserID),
		zap.Time("expiresAt", sessionData.ExpiresAt))
	return &sessionData, nil
}

// CreateSession creates a new session in Redis
func (m *AuthMiddleware) CreateSession(ctx context.Context, userID, email, accessToken, refreshToken string, expiresIn time.Duration) (string, error) {
	// Generate a unique session ID
	sessionID := generateSessionID()

	// Create session data
	sessionData := SessionData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
		Email:        email,
		ExpiresAt:    time.Now().Add(expiresIn),
		CreatedAt:    time.Now(),
	}

	// Marshal session data to JSON
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Store session in Redis
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	if err := m.redis.Set(ctx, sessionKey, sessionBytes, expiresIn).Err(); err != nil {
		return "", fmt.Errorf("failed to store session: %w", err)
	}

	m.logger.Debug("Created new session",
		zap.String("sessionID", sessionID),
		zap.String("userID", userID),
		zap.Time("expiresAt", sessionData.ExpiresAt))

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

// GetCookieName returns the cookie name
func (m *AuthMiddleware) GetCookieName() string {
	return m.cookieName
}

// RefreshJWKS forces a refresh of the JWKS cache
func (m *AuthMiddleware) RefreshJWKS() error {
	m.jwksCacheMutex.Lock()
	defer m.jwksCacheMutex.Unlock()

	m.jwksCache.Delete("jwks")
	m.logger.Debug("Cleared JWKS cache, will refresh on next request")

	// Immediately fetch new JWKS
	_, err := m.fetchJWKS()
	if err != nil {
		return fmt.Errorf("failed to refresh JWKS: %w", err)
	}

	return nil
}

// GetJWKSURL returns the current JWKS URL
func (m *AuthMiddleware) GetJWKSURL() string {
	return m.jwksURL
}
