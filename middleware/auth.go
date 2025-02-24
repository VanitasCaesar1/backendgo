// middleware/auth.go
package middleware

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type AuthMiddleware struct {
	logger     *zap.Logger
	redis      *redis.Client
	clientType string // e.g. "doctor", "user"
	cookieName string // e.g. "doctor_session", "auth_session"
}

type SessionData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

func NewAuthMiddleware(logger *zap.Logger, redis *redis.Client, clientType string, cookieName string) *AuthMiddleware {
	return &AuthMiddleware{
		logger:     logger,
		redis:      redis,
		clientType: clientType,
		cookieName: cookieName,
	}
}

func (m *AuthMiddleware) Handler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var sessionID string

		// Try Authorization header first
		auth := c.Get("Authorization")
		if auth != "" && strings.HasPrefix(auth, "Bearer ") {
			sessionID = strings.TrimPrefix(auth, "Bearer ")
		}

		// Fall back to cookie
		if sessionID == "" {
			sessionID = c.Cookies(m.cookieName)
		}

		if sessionID == "" {
			m.logger.Debug("no authentication found",
				zap.String("path", c.Path()),
				zap.String("clientType", m.clientType))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication required",
				"code":  "NO_SESSION",
			})
		}

		// Get session from Redis using client-specific prefix
		sessionKey := fmt.Sprintf("%s_session:%s", m.clientType, sessionID)
		sessionData, err := m.validateSession(c, sessionKey)
		if err != nil {
			m.logger.Debug("invalid session",
				zap.String("path", c.Path()),
				zap.Error(err))

			// Clear invalid cookie
			c.Cookie(&fiber.Cookie{
				Name:     m.cookieName,
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
		c.Locals("clientType", m.clientType)

		return c.Next()
	}
}

func (m *AuthMiddleware) validateSession(c *fiber.Ctx, sessionKey string) (*SessionData, error) {
	sessionBytes, err := m.redis.Get(c.Context(), sessionKey).Bytes()
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

	if time.Now().After(sessionData.ExpiresAt) {
		m.redis.Del(c.Context(), sessionKey)
		return nil, fmt.Errorf("session expired")
	}

	return &sessionData, nil
}
