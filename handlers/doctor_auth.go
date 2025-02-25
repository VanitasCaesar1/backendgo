// handlers/doctor_auth.go
package handlers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/VanitasCaesar1/backend/config"
	"github.com/VanitasCaesar1/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type DoctorAuthHandler struct {
	config         *config.Config
	redisClient    *redis.Client
	keycloakClient *gocloak.GoCloak
	pgPool         *pgxpool.Pool
	logger         *zap.Logger
	clientType     string // Add this field
}

func NewDoctorAuthHandler(cfg *config.Config, redis *redis.Client, pgPool *pgxpool.Pool, logger *zap.Logger) (*DoctorAuthHandler, error) {
	return &DoctorAuthHandler{
		config:         cfg,
		redisClient:    redis,
		keycloakClient: gocloak.NewClient(cfg.KeycloakURL),
		pgPool:         pgPool,
		logger:         logger,
		clientType:     "doctor", // Set the client type
	}, nil
}

type RegistrationRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

func (h *DoctorAuthHandler) Register(c *fiber.Ctx) error {
	var req RegistrationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Get admin token for creating user
	token, err := h.keycloakClient.LoginAdmin(
		c.Context(),
		h.config.KeycloakMasterUsername,
		h.config.KeycloakMasterPassword,
		h.config.KeycloakMasterRealm,
	)
	if err != nil {
		h.logger.Error("failed to get admin token", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Registration service temporarily unavailable",
		})
	}

	// Create user in Keycloak
	user := gocloak.User{
		Email:         &req.Email,
		Enabled:       gocloak.BoolP(true),
		EmailVerified: gocloak.BoolP(true),
		FirstName:     &req.FirstName,
		LastName:      &req.LastName,
		Username:      &req.Email,
		Attributes: &map[string][]string{
			"registration_date": {time.Now().Format(time.RFC3339)},
			"user_type":         {"doctor"},
		},
	}

	keycloakID, err := h.keycloakClient.CreateUser(
		c.Context(),
		token.AccessToken,
		h.config.RealmName,
		user,
	)
	if err != nil {
		h.logger.Error("failed to create user", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user account",
		})
	}

	// Set password
	err = h.keycloakClient.SetPassword(
		c.Context(),
		token.AccessToken,
		keycloakID,
		h.config.RealmName,
		req.Password,
		false,
	)
	if err != nil {
		// If password setting fails, clean up by deleting the created user
		h.keycloakClient.DeleteUser(
			c.Context(),
			token.AccessToken,
			h.config.RealmName,
			keycloakID,
		)
		h.logger.Error("failed to set password", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to set account password",
		})
	}

	// Begin database transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		// Clean up Keycloak user if DB transaction fails
		h.keycloakClient.DeleteUser(
			c.Context(),
			token.AccessToken,
			h.config.RealmName,
			keycloakID,
		)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user record",
		})
	}
	defer tx.Rollback(c.Context())

	parsedID, err := uuid.Parse(keycloakID)
	if err != nil {
		h.logger.Error("failed to parse keycloak ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process user ID",
		})
	}

	// Insert into users table
	_, err = tx.Exec(c.Context(),
		`INSERT INTO users (keycloak_id, email, name) 
     VALUES ($1, $2, $3)`,
		parsedID,
		req.Email,
		fmt.Sprintf("%s %s", req.FirstName, req.LastName),
	)
	if err != nil {
		h.logger.Error("failed to insert user", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user record",
		})
	}

	// Insert into roles table - updated to match new schema with main_role (singular)
	_, err = tx.Exec(c.Context(),
		`INSERT INTO roles (keycloak_id, main_role, scopes) 
     VALUES ($1, $2, $3)`,
		parsedID,
		"practitioner",
		nil, // Pass nil to represent NULL in the database
	)
	if err != nil {
		h.logger.Error("failed to insert role", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create role record",
		})
	}

	// Insert into user_sub_roles table for the doctor sub-role
	_, err = tx.Exec(c.Context(),
		`INSERT INTO user_sub_roles (keycloak_id, sub_role, assigned_by) 
     VALUES ($1, $2, $1)`, // The user is assigned their own role initially
		parsedID,
		"doctor",
	)
	if err != nil {
		h.logger.Error("failed to insert sub role", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create sub role record",
		})
	}

	if err = tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user records",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Registration successful",
		"userId":  keycloakID,
	})
}

func (h *DoctorAuthHandler) Login(c *fiber.Ctx) error {
	state := uuid.New().String()
	nonce := uuid.New().String()

	// Use consistent state key format
	stateKey := fmt.Sprintf("%s_state:%s", h.clientType, state)
	stateData := map[string]interface{}{
		"nonce":     nonce,
		"createdAt": time.Now(),
		"ip":        c.IP(),
		"userAgent": c.Get("User-Agent"),
	}

	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		h.logger.Error("failed to marshal state data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	err = h.redisClient.Set(c.Context(), stateKey, stateJSON, 10*time.Minute).Err()
	if err != nil {
		h.logger.Error("failed to store state in redis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Add scope parameter to auth URL
	authURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/auth?client_id=%s&response_type=code&state=%s&nonce=%s&redirect_uri=%s&scope=openid+profile+email",
		h.config.KeycloakURL,
		h.config.RealmName,
		h.config.KeycloakDoctorClientId,
		state,
		nonce,
		h.config.KeycloakDoctorRedirectURL,
	)

	return c.JSON(fiber.Map{
		"loginUrl": authURL,
	})
}

func (h *DoctorAuthHandler) Callback(c *fiber.Ctx) error {
	ctx := c.Context()
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		h.logger.Warn("missing code or state in callback",
			zap.String("ip", c.IP()),
			zap.String("user_agent", c.Get("User-Agent")),
		)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing code or state",
		})
	}

	// Use consistent state key format
	stateKey := fmt.Sprintf("%s_state:%s", h.clientType, state)
	stateJSON, err := h.redisClient.Get(ctx, stateKey).Bytes()
	if err != nil {
		h.logger.Error("failed to get state data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid state",
		})
	}

	var stateData struct {
		Nonce     string    `json:"nonce"`
		CreatedAt time.Time `json:"createdAt"`
		IP        string    `json:"ip"`
		UserAgent string    `json:"userAgent"`
	}

	if err := json.Unmarshal(stateJSON, &stateData); err != nil {
		h.logger.Error("failed to unmarshal state data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid state data",
		})
	}

	// Delete state immediately to prevent replay
	h.redisClient.Del(ctx, stateKey)

	// Exchange code for tokens with correct scope
	token, err := h.keycloakClient.GetToken(
		ctx,
		h.config.RealmName,
		gocloak.TokenOptions{
			ClientID:     &h.config.KeycloakDoctorClientId,
			ClientSecret: &h.config.KeycloakDoctorClientSecret,
			Code:         &code,
			GrantType:    gocloak.StringP("authorization_code"),
			RedirectURI:  &h.config.KeycloakDoctorRedirectURL,
			Scope:        gocloak.StringP("openid profile email"), // Add scopes here
		},
	)
	if err != nil {
		h.logger.Error("failed to exchange code for token",
			zap.Error(err),
			zap.String("code", code),
			zap.String("redirectUri", h.config.KeycloakDoctorRedirectURL))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to exchange token",
		})
	}

	// Get user info with token
	userInfo, err := h.keycloakClient.GetUserInfo(
		ctx,
		token.AccessToken,
		h.config.RealmName,
	)
	if err != nil {
		h.logger.Error("failed to get user info",
			zap.Error(err),
			zap.String("realmName", h.config.RealmName))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Failed to get user info",
			"details": err.Error(),
		})
	}

	// Create session
	sessionID := uuid.New().String()
	sessionKey := fmt.Sprintf("%s_session:%s", h.clientType, sessionID)

	sessionData := middleware.SessionData{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		UserID:       *userInfo.Sub,
		Email:        *userInfo.Email,
		ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		CreatedAt:    time.Now(),
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		h.logger.Error("failed to marshal session data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	err = h.redisClient.Set(ctx, sessionKey, sessionJSON, 24*time.Hour).Err()
	if err != nil {
		h.logger.Error("failed to store session in redis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Set session cookie
	cookieName := fmt.Sprintf("%s_session", h.clientType)
	c.Cookie(&fiber.Cookie{
		Name:     cookieName,
		Value:    sessionID,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		Domain:   h.config.CookieDomain,
	})

	return c.JSON(fiber.Map{
		"session": sessionID,
		"user": fiber.Map{
			"id":    *userInfo.Sub,
			"email": *userInfo.Email,
		},
	})
}

func (h *DoctorAuthHandler) Logout(c *fiber.Ctx) error {
	sessionID := c.Cookies("doctor_session")
	if sessionID != "" {
		sessionKey := fmt.Sprintf("doctor_session:%s", sessionID)
		h.redisClient.Del(c.Context(), sessionKey)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "doctor_session",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		Domain:   h.config.CookieDomain,
	})

	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}
