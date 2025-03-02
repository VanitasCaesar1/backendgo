package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/VanitasCaesar1/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
	"go.uber.org/zap"
)

type DoctorAuthHandler struct {
	config         *config.Config
	redisClient    *redis.Client
	logger         *zap.Logger
	pgPool         *pgxpool.Pool
	authMiddleware *middleware.AuthMiddleware
}

type DoctorRegistrationRequest struct {
	// User details
	Email      string  `json:"email"`
	Password   string  `json:"password"`
	Name       string  `json:"name"`
	Mobile     string  `json:"mobile"`
	BloodGroup string  `json:"bloodGroup"`
	Location   string  `json:"location"`
	Address    string  `json:"address"`
	Username   string  `json:"username"`
	ProfilePic string  `json:"profilePic"`
	HospitalID *string `json:"hospitalId"`

	// Doctor-specific details
	IMRNumber      string `json:"imrNumber"`
	Age            int    `json:"age"`
	Specialization string `json:"specialization"`
	Qualification  string `json:"qualification"`
	SlotDuration   int    `json:"slotDuration"`
}

type DoctorLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func NewDoctorAuthHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, pgPool *pgxpool.Pool, authMiddleware *middleware.AuthMiddleware) *DoctorAuthHandler {
	// Initialize WorkOS SDK
	usermanagement.SetAPIKey(cfg.WorkOSApiKey)

	return &DoctorAuthHandler{
		config:         cfg,
		redisClient:    rds,
		logger:         logger,
		pgPool:         pgPool,
		authMiddleware: authMiddleware,
	}
}

// tryDeleteWorkOSUser centralizes WorkOS user deletion to reduce code duplication
func (h *DoctorAuthHandler) tryDeleteWorkOSUser(ctx context.Context, workosUserID string, reason string) {
	if err := usermanagement.DeleteUser(
		ctx,
		usermanagement.DeleteUserOpts{
			User: workosUserID,
		},
	); err != nil {
		h.logger.Error("failed to delete WorkOS user after "+reason,
			zap.Error(err),
			zap.String("workos_id", workosUserID))
	}
}

// RegisterDoctor handles doctor registration
func (h *DoctorAuthHandler) RegisterDoctor(c *fiber.Ctx) error {
	var req DoctorRegistrationRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.Error("failed to parse registration request", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	// Check if user already exists with this email or username (combined query)
	var emailExists, usernameExists bool
	err := h.pgPool.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM users WHERE email = $1), EXISTS(SELECT 1 FROM users WHERE username = $2)",
		req.Email, req.Username).Scan(&emailExists, &usernameExists)
	if err != nil {
		h.logger.Error("failed to check user existence", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	if emailExists {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "This email is already registered",
		})
	}

	if usernameExists {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "This username is already taken",
		})
	}

	// Create user in WorkOS
	workosUser, err := usermanagement.CreateUser(
		c.Context(),
		usermanagement.CreateUserOpts{
			Email:     req.Email,
			Password:  req.Password,
			FirstName: strings.Split(req.Name, " ")[0],
			LastName:  strings.Join(strings.Split(req.Name, " ")[1:], " "),
		},
	)
	if err != nil {
		h.logger.Error("failed to create user in WorkOS", zap.Error(err))

		// Check for specific WorkOS errors
		if strings.Contains(err.Error(), "already exists") {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "This email is already registered",
			})
		}

		if strings.Contains(err.Error(), "password") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Invalid password",
				"message": "Password must be at least 8 characters",
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user account",
		})
	}

	// Create a transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		h.tryDeleteWorkOSUser(c.Context(), workosUser.ID, "transaction failure")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	defer tx.Rollback(c.Context()) // Rollback if not committed

	// Create user ID
	userID := uuid.New()

	// Parse mobile number
	var mobile int64
	_, err = fmt.Sscanf(req.Mobile, "%d", &mobile)
	if err != nil {
		h.logger.Error("failed to parse mobile number", zap.Error(err))
		h.tryDeleteWorkOSUser(c.Context(), workosUser.ID, "mobile parsing failure")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid mobile number format",
		})
	}

	// Insert into users table
	_, err = tx.Exec(c.Context(),
		`INSERT INTO users (
            user_id,
            profile_pic,
            name, 
            mobile, 
            email, 
            blood_group,
            location,
            address,
            username,
            hospital_id,
            auth_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		userID,
		req.ProfilePic,
		req.Name,
		mobile,
		req.Email,
		req.BloodGroup,
		req.Location,
		req.Address,
		req.Username,
		req.HospitalID,
		workosUser.ID,
	)
	if err != nil {
		h.logger.Error("failed to create user in database",
			zap.Error(err),
			zap.String("email", req.Email))
		h.tryDeleteWorkOSUser(c.Context(), workosUser.ID, "database failure")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user profile",
		})
	}

	// Insert into doctors table
	_, err = tx.Exec(c.Context(),
		`INSERT INTO doctors (
            doctor_id,
            name,
            imr_number,
            age,
            specialization,
            qualification,
            slot_duration,
            is_active
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		userID,
		req.Name,
		req.IMRNumber,
		req.Age,
		req.Specialization,
		req.Qualification,
		req.SlotDuration,
		false, // is_active defaults to false until verified
	)
	if err != nil {
		h.logger.Error("failed to create doctor in database",
			zap.Error(err),
			zap.String("email", req.Email))
		h.tryDeleteWorkOSUser(c.Context(), workosUser.ID, "database failure")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create doctor profile",
		})
	}

	// Commit the transaction
	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		h.tryDeleteWorkOSUser(c.Context(), workosUser.ID, "commit failure")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	h.logger.Info("doctor registration successful",
		zap.String("user_id", userID.String()),
		zap.String("auth_id", workosUser.ID),
		zap.String("email", req.Email))

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":   "Registration successful",
		"user_id":   userID.String(),
		"doctor_id": userID.String(),
	})
}

// LoginDoctor handles doctor login
func (h *DoctorAuthHandler) LoginDoctor(c *fiber.Ctx) error {
	var req DoctorLoginRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.Error("failed to parse login request", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	// Validate request
	if req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	// Authenticate with WorkOS
	authResponse, err := usermanagement.AuthenticateWithPassword(
		c.Context(),
		usermanagement.AuthenticateWithPasswordOpts{
			Email:    req.Email,
			Password: req.Password,
		},
	)
	if err != nil {
		h.logger.Error("WorkOS authentication failed",
			zap.Error(err),
			zap.String("email", req.Email))

		// Check if this is an invalid credentials error
		if strings.Contains(err.Error(), "invalid credentials") ||
			strings.Contains(err.Error(), "not found") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid email or password",
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Authentication failed",
		})
	}

	// Check if this user exists in our doctors table
	var doctorExists bool
	var userID uuid.UUID
	err = h.pgPool.QueryRow(c.Context(),
		`SELECT EXISTS(
			SELECT 1 FROM users u
			JOIN doctors d ON u.user_id = d.doctor_id
			WHERE u.auth_id = $1
		), u.user_id FROM users u WHERE u.auth_id = $1`,
		authResponse.User.ID).Scan(&doctorExists, &userID)
	if err != nil {
		h.logger.Error("failed to check doctor existence", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	if !doctorExists {
		h.logger.Warn("login attempt for non-doctor user",
			zap.String("email", req.Email),
			zap.String("auth_id", authResponse.User.ID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "This account is not registered as a doctor",
		})
	}

	// Create a session using the AuthMiddleware
	sessionID, err := h.authMiddleware.CreateSession(
		c.Context(),
		userID.String(),
		req.Email,
		authResponse.AccessToken,
		"",           // No refresh token in this flow
		24*time.Hour, // Session expiration
	)
	if err != nil {
		h.logger.Error("failed to create session", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create session",
		})
	}

	// Construct a login URL with the session ID
	loginUrl := fmt.Sprintf("%s/doctor/dashboard?token=%s", h.config.CookieDomain, sessionID)

	// Set the session cookie
	c.Cookie(&fiber.Cookie{
		Name:     h.authMiddleware.GetCookieName(),
		Value:    sessionID,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,
		Secure:   h.config.Environment != "development",
		SameSite: "Lax",
		Path:     "/",
	})

	return c.JSON(fiber.Map{
		"message":  "Login successful",
		"loginUrl": loginUrl,
		"token":    sessionID,
	})
}

// GetDoctorProfile retrieves a doctor's profile
func (h *DoctorAuthHandler) GetDoctorProfile(c *fiber.Ctx) error {
	// Get user ID from context (set by AuthMiddleware)
	userIDStr, ok := c.Locals("userID").(string)
	if !ok {
		h.logger.Error("userID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User not authenticated",
		})
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("invalid userID format", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	// Get doctor from database
	var doctorProfile struct {
		UserID         uuid.UUID  `json:"user_id"`
		DoctorID       uuid.UUID  `json:"doctor_id"`
		AuthID         string     `json:"auth_id"`
		Name           string     `json:"name"`
		Email          string     `json:"email"`
		Mobile         int64      `json:"mobile"`
		BloodGroup     string     `json:"blood_group"`
		Location       string     `json:"location"`
		Address        string     `json:"address"`
		Username       string     `json:"username"`
		ProfilePic     string     `json:"profile_pic"`
		HospitalID     *uuid.UUID `json:"hospital_id"`
		IMRNumber      string     `json:"imr_number"`
		Age            int        `json:"age"`
		Specialization string     `json:"specialization"`
		Qualification  string     `json:"qualification"`
		IsActive       bool       `json:"is_active"`
		SlotDuration   int        `json:"slot_duration"`
	}

	err = h.pgPool.QueryRow(c.Context(),
		`SELECT 
			u.user_id, 
			d.doctor_id,
			u.auth_id, 
			u.name,
			u.email, 
			u.mobile,
			u.blood_group,
			u.location,
			u.address,
			u.username,
			u.profile_pic,
			u.hospital_id,
			d.imr_number,
			d.age,
			d.specialization,
			d.qualification,
			d.is_active,
			d.slot_duration
		FROM users u
		JOIN doctors d ON u.user_id = d.doctor_id
		WHERE u.user_id = $1`,
		userID).Scan(
		&doctorProfile.UserID,
		&doctorProfile.DoctorID,
		&doctorProfile.AuthID,
		&doctorProfile.Name,
		&doctorProfile.Email,
		&doctorProfile.Mobile,
		&doctorProfile.BloodGroup,
		&doctorProfile.Location,
		&doctorProfile.Address,
		&doctorProfile.Username,
		&doctorProfile.ProfilePic,
		&doctorProfile.HospitalID,
		&doctorProfile.IMRNumber,
		&doctorProfile.Age,
		&doctorProfile.Specialization,
		&doctorProfile.Qualification,
		&doctorProfile.IsActive,
		&doctorProfile.SlotDuration,
	)

	if err != nil {
		h.logger.Error("failed to fetch doctor profile", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch doctor profile",
		})
	}

	return c.JSON(doctorProfile)
}

// DeleteDoctor handles doctor account deletion
func (h *DoctorAuthHandler) DeleteDoctor(c *fiber.Ctx) error {
	// Get user ID from context (set by AuthMiddleware)
	userIDStr, ok := c.Locals("userID").(string)
	if !ok {
		h.logger.Error("userID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User not authenticated",
		})
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("invalid userID format", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	// Get auth_id from database
	var authID string
	err = h.pgPool.QueryRow(c.Context(),
		"SELECT auth_id FROM users WHERE user_id = $1",
		userID).Scan(&authID)
	if err != nil {
		h.logger.Error("failed to get auth_id", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Start a transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	defer tx.Rollback(c.Context())

	// Delete from doctors table first (due to foreign key constraint)
	_, err = tx.Exec(c.Context(),
		"DELETE FROM doctors WHERE doctor_id = $1",
		userID)
	if err != nil {
		h.logger.Error("failed to delete doctor", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete doctor profile",
		})
	}

	// Delete from users table
	_, err = tx.Exec(c.Context(),
		"DELETE FROM users WHERE user_id = $1",
		userID)
	if err != nil {
		h.logger.Error("failed to delete user", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete user profile",
		})
	}

	// Commit transaction
	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	// Delete from WorkOS
	h.tryDeleteWorkOSUser(c.Context(), authID, "account deletion")

	// Clear any session data
	sessionID, ok := c.Locals("sessionID").(string)
	if ok && sessionID != "" {
		sessionKey := fmt.Sprintf("session:%s", sessionID)
		err = h.redisClient.Del(c.Context(), sessionKey).Err()
		if err != nil {
			h.logger.Error("failed to delete session from Redis", zap.Error(err))
			// Continue anyway
		}
	}

	return c.JSON(fiber.Map{
		"message": "Doctor account successfully deleted",
	})
}
