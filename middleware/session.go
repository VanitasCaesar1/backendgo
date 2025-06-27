package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/sso"
	"go.uber.org/zap"
)

// UserInfo represents the user data from WorkOS
type UserInfo struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	OrganizationID string `json:"organization_id"`
}

// SessionRequest represents the incoming session request from Next.js
type SessionRequest struct {
	User                 map[string]interface{} `json:"user"`
	AccessToken          string                 `json:"accessToken"`
	RefreshToken         string                 `json:"refreshToken"`
	OauthTokensScopes    []string               `json:"oauthTokensScopes"`
	OauthTokensExpiresAt int64                  `json:"oauthTokensExpiresAt"`
}

// AuthMiddleware struct for handling authentication
type AuthMiddleware struct {
	logger       *zap.Logger
	redis        *redis.Client
	workosClient *sso.Client
	config       *config.Config
	jwksCache    *sync.Map
	jwtSecret    []byte
	devMode      bool // For local development
}

// AuthMiddlewareConfig defines configuration for the auth middleware
type AuthMiddlewareConfig struct {
	Logger       *zap.Logger
	Redis        *redis.Client
	WorkosClient *sso.Client
	Config       *config.Config
	ClientID     string
	JWTSecret    string
	DevMode      bool
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config AuthMiddlewareConfig, c *config.Config) (*AuthMiddleware, error) {
	middleware := &AuthMiddleware{
		logger:       config.Logger,
		redis:        config.Redis,
		workosClient: config.WorkosClient,
		config:       config.Config,
		jwksCache:    &sync.Map{},
		jwtSecret:    []byte(c.JwtSecret),
		devMode:      config.DevMode,
	}

	return middleware, nil
}

// CreateSession creates a new session in Redis
func (m *AuthMiddleware) CreateSession(
	ctx context.Context,
	sessionID string, // Use the received sessionID instead of generating
	userID string,
	email string,
	accessToken string,
	refreshToken string,
	organizationID string,
	authID string,
	accessTokenExpiration time.Duration,
	refreshTokenExpiration time.Duration,
	userInfo map[string]interface{},
	userDetails map[string]interface{},
) (string, error) {
	// Create session data
	sessionData := SessionData{
		SessionID:      sessionID,
		AuthID:         authID,
		Email:          email,
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		OrganizationID: organizationID,
		ExpiresAt:      time.Now().Add(refreshTokenExpiration),
		UserInfo:       userInfo,
		UserDetails:    userDetails,
	}

	// Serialize session data
	sessionDataBytes, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Store session in Redis
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	err = m.redis.Set(ctx, sessionKey, sessionDataBytes, refreshTokenExpiration).Err()
	if err != nil {
		return "", fmt.Errorf("failed to store session: %w", err)
	}

	// Store refresh token mapping to session ID
	if refreshToken != "" {
		refreshTokenKey := fmt.Sprintf("refresh:%s", refreshToken)
		err = m.redis.Set(ctx, refreshTokenKey, sessionID, refreshTokenExpiration).Err()
		if err != nil {
			m.logger.Error("Failed to store refresh token mapping", zap.Error(err))
			// Continue anyway as this is not critical
		}
	}

	return sessionID, nil
}

// ValidateJWT validates a JWT token and returns the session data
func (m *AuthMiddleware) ValidateJWT(token string) (*SessionData, error) {
	// Implementation would go here
	// Use m.jwtSecret to validate the JWT signature
	// Parse the JWT claims to get the session data

	// Placeholder - replace with actual implementation
	var sessionData SessionData
	// Validate and parse JWT...
	return &sessionData, nil
}

// GenerateJWT generates a new JWT token for the session
func (m *AuthMiddleware) GenerateJWT(sessionData SessionData) (string, error) {
	// Implementation would go here
	// Use m.jwtSecret to sign the JWT

	// Placeholder - replace with actual implementation
	return "jwt_token_placeholder", nil
}

// CreateSessionHandler handles the session creation from WorkOS auth callback
func (m *AuthMiddleware) CreateSessionHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Parse the incoming request body
		var req SessionRequest
		if err := c.BodyParser(&req); err != nil {
			m.logger.Error("Failed to parse session request", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
				"code":  "INVALID_REQUEST",
			})
		}

		// Extract user info
		userInfo := req.User
		if userInfo == nil {
			m.logger.Error("Invalid user info format", zap.Any("user_info", req.User))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid user info format",
				"code":  "INVALID_USER_INFO",
			})
		}

		// Log the received data for debugging
		m.logger.Debug("Received session creation request",
			zap.Any("user", userInfo),
			zap.Bool("has_access_token", req.AccessToken != ""),
			zap.Bool("has_refresh_token", req.RefreshToken != ""),
			zap.Any("scopes", req.OauthTokensScopes))

		// Extract user ID and email
		userID, _ := userInfo["id"].(string)
		email, _ := userInfo["email"].(string)
		firstName, _ := userInfo["first_name"].(string)
		lastName, _ := userInfo["last_name"].(string)

		// Extract organization ID
		organizationID := ""
		if org, ok := userInfo["organization_id"].(string); ok {
			organizationID = org
		}

		// Use the WorkOS user ID as the auth ID
		authID := userID

		// Use the WorkOS user ID as the session ID
		// This matches what the frontend expects from withAuth()
		sessionID := userID

		// Set token expiration times
		accessTokenExpiration := time.Hour * 1       // 1 hour
		refreshTokenExpiration := time.Hour * 24 * 7 // 7 days

		// Create user details map
		userDetails := map[string]interface{}{
			"auth_id":         authID,
			"email":           email,
			"first_name":      firstName,
			"last_name":       lastName,
			"organization_id": organizationID,
		}

		// Create session
		sessionID, err := m.CreateSession(
			c.Context(),
			sessionID, // Use userID as the sessionID
			authID,
			email,
			req.AccessToken,
			req.RefreshToken,
			organizationID,
			authID,
			accessTokenExpiration,
			refreshTokenExpiration,
			userInfo,    // Store the user info
			userDetails, // Store user details
		)

		if err != nil {
			m.logger.Error("Failed to create session", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create session",
				"code":  "SESSION_CREATION_FAILED",
			})
		}

		// Log successful session creation
		m.logger.Info("Session created successfully",
			zap.String("session_id", sessionID),
			zap.String("user_id", authID),
			zap.String("email", email))

		// Return the session data with the user ID as session ID
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"session_id": sessionID,
			"token":      sessionID, // This is what the frontend will use as the Bearer token
			"user": fiber.Map{
				"auth_id":         authID,
				"email":           email,
				"first_name":      firstName,
				"last_name":       lastName,
				"organization_id": organizationID,
			},
			"expires_in": int(refreshTokenExpiration.Seconds()),
		})
	}
}

// Update the Handler middleware to validate using user ID
func (m *AuthMiddleware) Handler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user ID from Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" || len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Not authenticated",
				"code":  "AUTH_REQUIRED",
			})
		}

		// Extract user ID from Bearer token
		userID := authHeader[7:]
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid user ID",
				"code":  "INVALID_SESSION",
			})
		}

		// Log the received user ID for debugging
		m.logger.Debug("Validating session",
			zap.String("user_id", userID))

		// Check if session exists in Redis using user ID as key
		sessionKey := fmt.Sprintf("session:%s", userID)
		exists, err := m.redis.Exists(c.Context(), sessionKey).Result()
		if err != nil || exists == 0 {
			m.logger.Debug("Session not found in Redis",
				zap.String("user_id", userID),
				zap.Error(err))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Session not found",
				"code":  "SESSION_NOT_FOUND",
			})
		}

		// Get the session data from Redis
		sessionDataJSON, err := m.redis.Get(c.Context(), sessionKey).Result()
		if err != nil {
			m.logger.Error("Failed to get session data from Redis",
				zap.String("user_id", userID),
				zap.Error(err))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Session data unavailable",
				"code":  "SESSION_DATA_UNAVAILABLE",
			})
		}

		// Parse the session data
		var sessionData SessionData
		if err := json.Unmarshal([]byte(sessionDataJSON), &sessionData); err != nil {
			m.logger.Error("Failed to parse session data",
				zap.String("user_id", userID),
				zap.String("raw_data", sessionDataJSON),
				zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal server error",
				"code":  "INTERNAL_ERROR",
			})
		}

		// Check if the session has expired
		if time.Now().After(sessionData.ExpiresAt) {
			m.logger.Debug("Session expired",
				zap.String("user_id", userID),
				zap.Time("expires_at", sessionData.ExpiresAt))

			// Delete the expired session
			m.redis.Del(c.Context(), sessionKey)

			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Session expired",
				"code":  "SESSION_EXPIRED",
			})
		}

		// Set values in context for use in downstream handlers
		if sessionData.AuthID != "" {
			c.Locals("authID", sessionData.AuthID)
		}
		if sessionData.Email != "" {
			c.Locals("email", sessionData.Email)
		}
		if sessionData.OrganizationID != "" {
			c.Locals("organizationID", sessionData.OrganizationID)
		}
		c.Locals("userID", userID)

		// Store the full user details if available
		if sessionData.UserDetails != nil {
			for k, v := range sessionData.UserDetails {
				c.Locals(k, v)
			}
		}

		// Update last activity timestamp
		m.redis.HSet(c.Context(),
			fmt.Sprintf("session_activity:%s", userID),
			"last_activity", time.Now().Unix(),
			"path", c.Path(),
			"method", c.Method(),
		)

		m.logger.Debug("Session validated successfully",
			zap.String("user_id", userID),
			zap.String("email", sessionData.Email))

		return c.Next()
	}
}

// Update the LogoutHandler to use user ID
func (m *AuthMiddleware) LogoutHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user ID from Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" || len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "No session token provided",
				"code":  "NO_SESSION_TOKEN",
			})
		}

		// Extract user ID
		userID := authHeader[7:]

		// Check if session exists in Redis
		sessionKey := fmt.Sprintf("session:%s", userID)
		exists, err := m.redis.Exists(c.Context(), sessionKey).Result()
		if err != nil || exists == 0 {
			// Session doesn't exist, but return success anyway
			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"message": "Logged out successfully",
			})
		}

		// Delete the session and activity data
		m.redis.Del(c.Context(), sessionKey)
		m.redis.Del(c.Context(), fmt.Sprintf("session_activity:%s", userID))

		// Delete refresh token if exists
		sessionDataJSON, err := m.redis.Get(c.Context(), sessionKey).Result()
		if err == nil {
			var sessionData SessionData
			if err := json.Unmarshal([]byte(sessionDataJSON), &sessionData); err == nil {
				if sessionData.RefreshToken != "" {
					refreshTokenKey := fmt.Sprintf("refresh:%s", sessionData.RefreshToken)
					m.redis.Del(c.Context(), refreshTokenKey)
				}
			}
		}

		m.logger.Info("User logged out",
			zap.String("user_id", userID))

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Logged out successfully",
		})
	}
}

// SessionData structure for storing session information
type SessionData struct {
	SessionID      string                 `json:"session_id"`
	UserID         string                 `json:"user_id"`
	AuthID         string                 `json:"auth_id"`
	Email          string                 `json:"email"`
	AccessToken    string                 `json:"access_token"`
	RefreshToken   string                 `json:"refresh_token"`
	OrganizationID string                 `json:"organization_id"`
	ExpiresAt      time.Time              `json:"expires_at"`
	UserInfo       map[string]interface{} `json:"user_info"`
	UserDetails    map[string]interface{} `json:"user_details"`
}

// SetupSessionMiddleware configures and initializes the auth middleware
func SetupSessionMiddleware(app *fiber.App, logger *zap.Logger, redis *redis.Client, config *config.Config) {
	// Initialize WorkOS client if needed
	// workosClient := sso.NewClient(config.WorkOSApiKey)

	// Create the auth middleware
	authMiddlewareConfig := AuthMiddlewareConfig{
		Logger: logger,
		Redis:  redis,
		Config: config,
		// WorkosClient: workosClient,
		ClientID:  config.WorkOSClientId,
		JWTSecret: config.JwtSecret,
		DevMode:   config.Environment != "production",
	}

	authMiddleware, err := NewAuthMiddleware(authMiddlewareConfig, config)
	if err != nil {
		logger.Fatal("Failed to create auth middleware", zap.Error(err))
	}

	logger.Info("Auth middleware setup complete",
		zap.Bool("dev_mode", authMiddleware.devMode),
		zap.String("workos_client_id", config.WorkOSClientId))
}

// dd
