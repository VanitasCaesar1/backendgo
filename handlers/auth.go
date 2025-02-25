// handlers/auth.go
package handlers

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type AuthHandler struct {
	config       *config.Config
	redisClient  *redis.Client
	oauth2Config *oauth2.Config
	publicKey    *rsa.PublicKey
	logger       *zap.Logger
	rateLimiter  *RateLimiter
	clientType   string // Added for client type handling
	cookieName   string // Added for cookie name handling
}

// SessionData represents the structure of session data stored in Redis
type SessionData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// RateLimiter handles rate limiting logic
type RateLimiter struct {
	redisClient *redis.Client
	window      time.Duration
	limit       int
}

// NewRateLimiter creates a new rate limiter instance
func NewRateLimiter(redisClient *redis.Client, window time.Duration, limit int) *RateLimiter {
	return &RateLimiter{
		redisClient: redisClient,
		window:      window,
		limit:       limit,
	}
}

// IsLimited checks if the request should be rate limited
func (rl *RateLimiter) IsLimited(ctx context.Context, key string) (bool, error) {
	now := time.Now().Unix()
	windowKey := fmt.Sprintf("ratelimit:%s:%d", key, now/int64(rl.window.Seconds()))

	pipe := rl.redisClient.Pipeline()
	incr := pipe.Incr(ctx, windowKey)
	pipe.Expire(ctx, windowKey, rl.window)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return true, fmt.Errorf("rate limit check failed: %w", err)
	}

	count, err := incr.Result()
	if err != nil {
		return true, fmt.Errorf("failed to get rate limit count: %w", err)
	}

	return count > int64(rl.limit), nil
}

// NewAuthHandler creates a new instance of AuthHandler
func NewAuthHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, clientType string, cookieName string) (*AuthHandler, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	cfg.KeycloakURL = strings.TrimSuffix(cfg.KeycloakURL, "/")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	rateLimiter := NewRateLimiter(rds, time.Minute, 6)

	return &AuthHandler{
		config:      cfg,
		redisClient: rds,
		oauth2Config: &oauth2.Config{
			ClientID:     cfg.KeycloakClientID,
			ClientSecret: cfg.KeycloakClientSecret,
			RedirectURL:  cfg.KeycloakRedirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", cfg.KeycloakURL, cfg.RealmName),
				TokenURL: fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", cfg.KeycloakURL, cfg.RealmName),
			},
		},
		publicKey:   publicKey,
		logger:      logger,
		rateLimiter: rateLimiter,
		clientType:  clientType,
		cookieName:  cookieName,
	}, nil
}

// validateConfig validates the configuration
func validateConfig(cfg *config.Config) error {
	if cfg.KeycloakURL == "" {
		return fmt.Errorf("KeycloakURL cannot be empty")
	}
	if cfg.KeycloakClientID == "" {
		return fmt.Errorf("KeycloakClientID cannot be empty")
	}
	if cfg.KeycloakClientSecret == "" {
		return fmt.Errorf("KeycloakClientSecret cannot be empty")
	}
	if cfg.KeycloakRedirectURL == "" {
		return fmt.Errorf("KeycloakRedirectURL cannot be empty")
	}
	if cfg.RealmName == "" {
		return fmt.Errorf("RealmName cannot be empty")
	}
	if cfg.PublicKey == "" {
		return fmt.Errorf("PublicKey cannot be empty")
	}
	return nil
}

// Login initiates the OAuth2 login flow
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	ctx := c.Context()

	// Rate limiting check
	limited, err := h.rateLimiter.IsLimited(ctx, c.IP())
	if err != nil {
		h.logger.Error("rate limit check failed", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	if limited {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": "Too many login attempts",
		})
	}

	// Generate and store state with additional security measures
	state := uuid.New().String()
	nonce := uuid.New().String()

	stateData := struct {
		State     string    `json:"state"`
		Nonce     string    `json:"nonce"`
		IP        string    `json:"ip"`
		UserAgent string    `json:"user_agent"`
		CreatedAt time.Time `json:"created_at"`
	}{
		State:     state,
		Nonce:     nonce,
		IP:        c.IP(),
		UserAgent: c.Get("User-Agent"),
		CreatedAt: time.Now(),
	}

	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		h.logger.Error("failed to marshal state data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to initialize login",
		})
	}

	// Store state with additional security info
	err = h.redisClient.Set(ctx, fmt.Sprintf("state:%s", state), stateJSON, time.Minute*10).Err()
	if err != nil {
		h.logger.Error("failed to store state", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to initialize login",
		})
	}

	// Add nonce to OAuth config
	authURL := h.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
	)

	// Clear any existing session
	c.ClearCookie("auth_session")

	h.logger.Info("redirecting to keycloak login",
		zap.String("state", state),
		zap.String("redirect_url", authURL),
	)

	return c.Redirect(authURL, fiber.StatusTemporaryRedirect)
}

// Add this method to AuthHandler
func (h *AuthHandler) getRequestIdentifiers(c *fiber.Ctx) (string, string) {
	// Get original user agent and IP from headers if present
	userAgent := c.Get("X-Original-User-Agent")
	if userAgent == "" {
		userAgent = c.Get("User-Agent")
	}

	// For IP, check multiple possible headers
	ip := c.Get("X-Original-For")
	if ip == "" {
		ip = c.Get("X-Forwarded-For")
		if ip == "" {
			ip = c.Get("X-Real-IP")
			if ip == "" {
				ip = c.IP()
			}
		}
		// If X-Forwarded-For contains multiple IPs, take the first one
		if strings.Contains(ip, ",") {
			ip = strings.TrimSpace(strings.Split(ip, ",")[0])
		}
	}

	return ip, userAgent
}

// Update the Callback method validation section
func (h *AuthHandler) Callback(c *fiber.Ctx) error {
	ctx := c.Context()
	state, code := h.extractStateAndCode(c)

	if state == "" || code == "" {
		h.logger.Warn("missing state or code in callback",
			zap.String("ip", c.IP()),
			zap.String("user_agent", c.Get("User-Agent")),
		)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing state or code",
		})
	}

	// Get and validate stored state data
	stateKey := fmt.Sprintf("state:%s", state)
	stateJSON, err := h.redisClient.Get(ctx, stateKey).Bytes()
	if err != nil {
		h.logger.Error("failed to get state data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid state",
		})
	}

	var stateData struct {
		State     string    `json:"state"`
		Nonce     string    `json:"nonce"`
		IP        string    `json:"ip"`
		UserAgent string    `json:"user_agent"`
		CreatedAt time.Time `json:"created_at"`
	}

	if err := json.Unmarshal(stateJSON, &stateData); err != nil {
		h.logger.Error("failed to unmarshal state data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid state data",
		})
	}

	// Get current request identifiers
	currentIP, currentUA := h.getRequestIdentifiers(c)

	// Only perform strict validation in non-development environments
	if !h.config.IsDevelopment() {
		// Validate IP
		if stateData.IP != currentIP {
			h.logger.Warn("IP mismatch in callback",
				zap.String("original_ip", stateData.IP),
				zap.String("current_ip", currentIP),
			)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request origin",
			})
		}

		// Strict User-Agent validation in production
		if stateData.UserAgent != currentUA {
			h.logger.Warn("User-Agent mismatch in callback",
				zap.String("original_ua", stateData.UserAgent),
				zap.String("current_ua", currentUA),
			)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request origin",
			})
		}
	} else {
		// In development, log mismatches but don't reject the request
		if stateData.IP != currentIP || stateData.UserAgent != currentUA {
			h.logger.Info("request identifier mismatch in development",
				zap.String("original_ip", stateData.IP),
				zap.String("current_ip", currentIP),
				zap.String("original_ua", stateData.UserAgent),
				zap.String("current_ua", currentUA),
			)
		}
	}

	// Delete state immediately to prevent replay
	h.redisClient.Del(ctx, stateKey)

	// Continue with token exchange and session creation
	token, err := h.oauth2Config.Exchange(ctx, code)
	if err != nil {
		h.logger.Error("token exchange failed", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to exchange token",
		})
	}

	claims, err := h.validateIDTokenWithNonce(token, stateData.Nonce)
	if err != nil {
		h.logger.Error("ID token validation failed", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid ID token",
		})
	}

	sessionID, err := h.createSession(ctx, token, claims)
	if err != nil {
		h.logger.Error("session creation failed", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create session",
		})
	}

	// Set cookie domain based on configuration
	h.setSessionCookie(c, sessionID)

	h.logger.Info("login successful",
		zap.String("user_id", claims["sub"].(string)),
		zap.String("session_id", sessionID),
	)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"session": sessionID,
		"user": fiber.Map{
			"id":    claims["sub"],
			"email": claims["email"],
		},
	})
}

// Add this new method for nonce validation
func (h *AuthHandler) validateIDTokenWithNonce(token *oauth2.Token, expectedNonce string) (jwt.MapClaims, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token found")
	}

	parsed, err := jwt.Parse(rawIDToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	// Validate nonce
	if nonce, ok := claims["nonce"].(string); !ok || nonce != expectedNonce {
		return nil, fmt.Errorf("invalid nonce")
	}

	if err := h.validateClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// AuthMiddleware authenticates requests
func (h *AuthHandler) AuthMiddleware(c *fiber.Ctx) error {
	ctx := c.Context()
	sessionID := c.Cookies("auth_session")
	if sessionID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "No session found",
		})
	}

	sessionKey := fmt.Sprintf("session:%s", sessionID)
	exists, err := h.redisClient.Exists(ctx, sessionKey).Result()
	if err != nil {
		h.logger.Error("session check failed", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Server error",
		})
	}

	if exists == 0 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid session",
		})
	}

	// Get session data
	sessionBytes, err := h.redisClient.Get(ctx, sessionKey).Bytes()
	if err != nil {
		h.logger.Error("failed to get session data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Server error",
		})
	}

	var sessionData SessionData
	if err := json.Unmarshal(sessionBytes, &sessionData); err != nil {
		h.logger.Error("failed to unmarshal session data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Server error",
		})
	}

	// Check token expiration
	if time.Now().After(sessionData.ExpiresAt) {
		// Token is expired, try to refresh
		if err := h.refreshSession(ctx, sessionID); err != nil {
			h.logger.Error("session refresh failed", zap.Error(err))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Session expired",
			})
		}

		// Get updated session data after refresh
		sessionBytes, err = h.redisClient.Get(ctx, sessionKey).Bytes()
		if err != nil {
			h.logger.Error("failed to get refreshed session data", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Server error",
			})
		}

		if err := json.Unmarshal(sessionBytes, &sessionData); err != nil {
			h.logger.Error("failed to unmarshal refreshed session data", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Server error",
			})
		}
	}

	// Set user info in context
	c.Locals("userID", sessionData.UserID)
	c.Locals("email", sessionData.Email)

	return c.Next()
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	h.logger.Info("Logout request received")
	ctx := c.Context()

	// Get current session using the correct cookie name
	sessionID := c.Cookies(h.cookieName)
	var idToken string

	if sessionID != "" {
		// Get session data to retrieve ID token
		sessionKey := fmt.Sprintf("%s_session:%s", h.clientType, sessionID)
		var sessionData SessionData
		sessionBytes, err := h.redisClient.Get(ctx, sessionKey).Bytes()
		if err == nil {
			if err := json.Unmarshal(sessionBytes, &sessionData); err == nil {
				idToken = sessionData.IDToken
				h.logger.Info("Retrieved ID token for logout", zap.Bool("id_token_present", idToken != ""))
			}
		}

		// Clean up local session
		if err := h.performLocalLogout(c); err != nil {
			h.logger.Error("local logout failed", zap.Error(err))
			// Continue with Keycloak logout even if local logout fails
		}
	}

	// Build Keycloak end-session URL
	logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout",
		h.config.KeycloakURL,
		h.config.RealmName)

	// Add required parameters
	params := url.Values{}

	// Add post_logout_redirect_uri if configured
	if h.config.PostLogoutURI != "" {
		params.Add("post_logout_redirect_uri", h.config.PostLogoutURI)
		// Ensure client_id is provided with redirect_uri
		params.Add("client_id", h.config.KeycloakClientID)
	}

	// Add id_token_hint if available - this is CRITICAL for ending the SSO session
	if idToken != "" {
		params.Add("id_token_hint", idToken)
	}

	// Add state parameter for security
	state := uuid.New().String()
	params.Add("state", state)

	// Store state temporarily for validation
	if err := h.redisClient.Set(ctx,
		fmt.Sprintf("%s_logout_state:%s", h.clientType, state),
		"true",
		5*time.Minute).Err(); err != nil {
		h.logger.Error("failed to store logout state", zap.Error(err))
	}

	// Construct final logout URL
	finalLogoutURL := fmt.Sprintf("%s?%s", logoutURL, params.Encode())

	h.logger.Info("redirecting to Keycloak logout",
		zap.String("logout_url", finalLogoutURL))

	// Redirect to Keycloak's logout endpoint
	return c.Redirect(finalLogoutURL, fiber.StatusTemporaryRedirect)
}

// LogoutCallback handles the return from Keycloak after logout
func (h *AuthHandler) LogoutCallback(c *fiber.Ctx) error {
	state := c.Query("state")

	if state != "" {
		// Validate state
		stateKey := fmt.Sprintf("logout_state:%s", state)
		exists, err := h.redisClient.Exists(c.Context(), stateKey).Result()
		if err != nil {
			h.logger.Error("failed to check logout state", zap.Error(err))
		} else if exists == 1 {
			// Clean up state
			h.redisClient.Del(c.Context(), stateKey)
		}
	}

	// If PostLogoutURI is configured, redirect there
	if h.config.PostLogoutURI != "" {
		return c.Redirect(h.config.PostLogoutURI, fiber.StatusTemporaryRedirect)
	}

	// Otherwise return success
	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}

// Improve the performLocalLogout method to be more thorough
func (h *AuthHandler) performLocalLogout(c *fiber.Ctx) error {
	ctx := c.Context()
	sessionID := c.Cookies(h.cookieName)

	if sessionID != "" {
		if err := h.deleteSession(ctx, sessionID); err != nil {
			return fmt.Errorf("failed to delete session: %w", err)
		}
	}

	// Clear the cookie in both root domain and specified domain if any
	c.Cookie(&fiber.Cookie{
		Name:     h.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   h.config.CookieDomain,
		MaxAge:   -1,
		Expires:  time.Now().Add(-24 * time.Hour),
		Secure:   !h.config.IsDevelopment(),
		HTTPOnly: true,
		SameSite: "Lax",
	})

	// Also clear without domain to handle cases where cookie was set without domain
	if h.config.CookieDomain != "" {
		c.Cookie(&fiber.Cookie{
			Name:     h.cookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Now().Add(-24 * time.Hour),
			Secure:   !h.config.IsDevelopment(),
			HTTPOnly: true,
			SameSite: "Lax",
		})
	}

	return nil
}

// Fix the deleteSession method to use the correct revocation endpoint
func (h *AuthHandler) deleteSession(ctx context.Context, sessionID string) error {
	sessionKey := fmt.Sprintf("%s_session:%s", h.clientType, sessionID)
	var sessionData SessionData

	sessionBytes, err := h.redisClient.Get(ctx, sessionKey).Bytes()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("failed to get session data: %w", err)
	}

	if err == nil {
		if err := json.Unmarshal(sessionBytes, &sessionData); err == nil {
			if sessionData.RefreshToken != "" {
				if err := h.revokeToken(ctx, sessionData.RefreshToken); err != nil {
					h.logger.Warn("failed to revoke token at Keycloak", zap.Error(err))
				}
			}

			pipe := h.redisClient.Pipeline()
			pipe.Del(ctx, sessionKey)
			pipe.Del(ctx, fmt.Sprintf("%s_user_session:%s", h.clientType, sessionData.UserID))
			pipe.Del(ctx, fmt.Sprintf("%s_auth_state:%s", h.clientType, sessionID))

			if _, err := pipe.Exec(ctx); err != nil {
				return fmt.Errorf("failed to delete session data: %w", err)
			}
		}
	}

	return nil
}

// Fix the revokeToken method to use the correct revocation endpoint
func (h *AuthHandler) revokeToken(ctx context.Context, refreshToken string) error {
	// Build form data
	formData := url.Values{}
	formData.Set("client_id", h.config.KeycloakClientID)
	formData.Set("client_secret", h.config.KeycloakClientSecret)
	formData.Set("token", refreshToken)
	formData.Set("token_type_hint", "refresh_token")

	// Use the proper revocation endpoint
	revokeURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/revoke",
		h.config.KeycloakURL,
		h.config.RealmName)

	req, err := http.NewRequestWithContext(ctx, "POST", revokeURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for better error reporting
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to revoke token, status: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RefreshToken refreshes the access token
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	ctx := c.Context()
	sessionID := c.Cookies("auth_session")
	if sessionID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "No session found",
		})
	}

	if err := h.refreshSession(ctx, sessionID); err != nil {
		h.logger.Error("token refresh failed", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to refresh token",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Token refreshed successfully",
	})
}

// Helper methods

func (h *AuthHandler) extractStateAndCode(c *fiber.Ctx) (string, string) {
	var state, code string

	if c.Method() == "POST" {
		var body struct {
			State string `json:"state"`
			Code  string `json:"code"`
		}
		if err := c.BodyParser(&body); err == nil {
			state = body.State
			code = body.Code
		}
	}

	if state == "" {
		state = c.Query("state")
	}
	if code == "" {
		code = c.Query("code")
	}

	return state, code
}

func (h *AuthHandler) validateIDToken(token *oauth2.Token) (jwt.MapClaims, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token found")
	}

	parsed, err := jwt.Parse(rawIDToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	if err := h.validateClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// Update the validateClaims function to handle the issuer URL properly:
func (h *AuthHandler) validateClaims(claims jwt.MapClaims) error {
	now := time.Now().Unix()

	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < now {
			return fmt.Errorf("token expired")
		}
	}

	if iat, ok := claims["iat"].(float64); ok {
		if int64(iat) > now {
			return fmt.Errorf("token issued in the future")
		}
	}

	// Construct expected issuer URL if not provided in config
	expectedIssuer := h.config.ExpectedIssuer
	if expectedIssuer == "" {
		expectedIssuer = fmt.Sprintf("%s/realms/%s", h.config.KeycloakURL, h.config.RealmName)
	}

	// Construct expected audience if not provided in config
	expectedAudience := h.config.ExpectedAudience
	if expectedAudience == "" {
		expectedAudience = h.config.KeycloakClientID
	}

	if iss, ok := claims["iss"].(string); !ok || iss != expectedIssuer {
		return fmt.Errorf("invalid issuer")
	}

	if aud, ok := claims["aud"].(string); !ok || aud != expectedAudience {
		return fmt.Errorf("invalid audience")
	}

	requiredClaims := []string{"sub", "email"}
	for _, claim := range requiredClaims {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	return nil
}

// NEED TO ADD CLAIMS TO INTEGRATE FINE GRAINED AUTH LIKE ROLES
// ATTRIBUTES ETC

func (h *AuthHandler) createSession(ctx context.Context, token *oauth2.Token, claims jwt.MapClaims) (string, error) {
	sessionID := uuid.New().String()
	sessionKey := fmt.Sprintf("%s_session:%s", h.clientType, sessionID)

	sessionData := SessionData{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      token.Extra("id_token").(string),
		UserID:       claims["sub"].(string),
		Email:        claims["email"].(string),
		ExpiresAt:    token.Expiry,
		CreatedAt:    time.Now(),
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}

	pipe := h.redisClient.Pipeline()
	pipe.Set(ctx, sessionKey, sessionJSON, time.Hour*24)
	pipe.Set(ctx, fmt.Sprintf("%s_user_session:%s", h.clientType, sessionData.UserID), sessionID, time.Hour*24)

	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("failed to store session: %w", err)
	}

	return sessionID, nil
}

func (h *AuthHandler) refreshSession(ctx context.Context, sessionID string) error {
	sessionKey := fmt.Sprintf("session:%s", sessionID)

	// Get existing session data
	var sessionData SessionData
	sessionJSON, err := h.redisClient.Get(ctx, sessionKey).Bytes()
	if err != nil {
		return fmt.Errorf("failed to get session data: %w", err)
	}

	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		return fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// Create token source with refresh token
	tokenSource := h.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: sessionData.RefreshToken,
	})

	// Get new token
	newToken, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	// Validate new token
	claims, err := h.validateIDToken(newToken)
	if err != nil {
		return fmt.Errorf("invalid refreshed token: %w", err)
	}

	// Update session data
	sessionData.AccessToken = newToken.AccessToken
	if newToken.RefreshToken != "" { // Some providers don't always return a new refresh token
		sessionData.RefreshToken = newToken.RefreshToken
	}
	sessionData.IDToken = newToken.Extra("id_token").(string)
	sessionData.ExpiresAt = newToken.Expiry

	// Store updated session
	updatedSessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session: %w", err)
	}

	pipe := h.redisClient.Pipeline()
	pipe.Set(ctx, sessionKey, updatedSessionJSON, time.Hour*24)
	pipe.Set(ctx, fmt.Sprintf("user_session:%s", claims["sub"].(string)), sessionID, time.Hour*24)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to store updated session: %w", err)
	}

	return nil
}

func (h *AuthHandler) setSessionCookie(c *fiber.Ctx, sessionID string) {
	cookie := fiber.Cookie{
		Name:     h.cookieName,
		Value:    sessionID,
		Path:     "/",
		Domain:   h.config.CookieDomain,
		MaxAge:   int(time.Hour * 24 / time.Second),
		Secure:   !h.config.IsDevelopment(),
		HTTPOnly: true,
		SameSite: "Lax",
	}
	c.Cookie(&cookie)
}

// GetUserInfo retrieves user information from the session
func (h *AuthHandler) GetUserInfo(c *fiber.Ctx) error {
	userID := c.Locals("userID").(string)
	email := c.Locals("email").(string)

	return c.JSON(fiber.Map{
		"user": fiber.Map{
			"id":    userID,
			"email": email,
		},
	})
}

// RevokeAllSessions revokes all active sessions for a user
func (h *AuthHandler) RevokeAllSessions(c *fiber.Ctx) error {
	ctx := c.Context()
	userID := c.Locals("userID").(string)

	// Get current user's session ID
	sessionID, err := h.redisClient.Get(ctx, fmt.Sprintf("user_session:%s", userID)).Result()
	if err != nil && err != redis.Nil {
		h.logger.Error("failed to get user session", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to revoke sessions",
		})
	}

	// Delete session and user session mapping
	pipe := h.redisClient.Pipeline()
	pipe.Del(ctx, fmt.Sprintf("session:%s", sessionID))
	pipe.Del(ctx, fmt.Sprintf("user_session:%s", userID))

	if _, err := pipe.Exec(ctx); err != nil {
		h.logger.Error("failed to delete sessions", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to revoke sessions",
		})
	}

	c.ClearCookie("auth_session")

	return c.JSON(fiber.Map{
		"message": "All sessions revoked successfully",
	})
}
