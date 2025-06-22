package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/VanitasCaesar1/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/zap"
)

type DoctorAuthHandler struct {
	config         *config.Config
	redisClient    *redis.Client
	logger         *zap.Logger
	mongoClient    *mongo.Client
	pgPool         *pgxpool.Pool
	authMiddleware *middleware.AuthMiddleware
}

type DoctorRegistrationRequest struct {
	// User details
	Email      string `json:"email"`
	Password   string `json:"password"`
	Name       string `json:"name"`
	Mobile     string `json:"mobile"`
	BloodGroup string `json:"bloodGroup"`
	Location   string `json:"location"`
	Address    string `json:"address"`
	Username   string `json:"username"`
	ProfilePic string `json:"profilePic"`
	HospitalID string `json:"hospitalId"`
	AadhaarID  string `json:"aadhaar_id"`

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

func NewDoctorAuthHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, pgPool *pgxpool.Pool, mongoClient *mongo.Client, authMiddleware *middleware.AuthMiddleware) *DoctorAuthHandler {
	// Initialize WorkOS SDK
	usermanagement.SetAPIKey(cfg.WorkOSApiKey)

	return &DoctorAuthHandler{
		config:         cfg,
		redisClient:    rds,
		mongoClient:    mongoClient,
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

func (h *DoctorAuthHandler) RegisterDoctor(c *fiber.Ctx) error {
	var req DoctorRegistrationRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.Error("failed to parse registration request", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	if req.AadhaarID != "" {
		aadhaarRegex := regexp.MustCompile(`^\d{12}$`)
		if !aadhaarRegex.MatchString(req.AadhaarID) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid Aadhaar ID format. Must be exactly 12 digits.",
			})
		}
	}

	// Check if user already exists with this email, username, or Aadhaar ID
	var emailExists, usernameExists, aadhaarExists bool
	err := h.pgPool.QueryRow(c.Context(),
		`SELECT
            EXISTS(SELECT 1 FROM users WHERE email = $1),
            EXISTS(SELECT 1 FROM users WHERE username = $2),
            EXISTS(SELECT 1 FROM users WHERE aadhaar_id = $3)`,
		req.Email, req.Username, req.AadhaarID).Scan(&emailExists, &usernameExists, &aadhaarExists)
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
	if aadhaarExists {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "This Aadhaar ID is already registered",
		})
	}

	// Create user ID first so we can use it as ExternalID in WorkOS
	userID := uuid.New()

	// Create user in WorkOS with the userID as ExternalID
	workosUser, err := usermanagement.CreateUser(
		c.Context(),
		usermanagement.CreateUserOpts{
			Email:      req.Email,
			Password:   req.Password,
			FirstName:  strings.Split(req.Name, " ")[0],
			LastName:   strings.Join(strings.Split(req.Name, " ")[1:], " "),
			ExternalID: userID.String(),
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

	// Assuming req.Specialization is a string or struct that needs to be converted to JSON
	// Convert string value to JSON object
	var specializationJSON string
	if req.Specialization != "" {
		// Create a simple JSON object with a "name" field
		specializationJSON = fmt.Sprintf(`{"name":"%s"}`, req.Specialization)
	} else {
		specializationJSON = "{}"
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
	var insertedUserID uuid.UUID
	err = tx.QueryRow(c.Context(),
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
            aadhaar_id,
            auth_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING user_id`,
		userID, // Use the pre-generated UUID
		req.ProfilePic,
		req.Name,
		mobile,
		req.Email,
		req.BloodGroup,
		req.Location,
		req.Address,
		req.Username,
		nil, // hospital_id - using nil for NULL
		req.AadhaarID,
		workosUser.ID,
	).Scan(&insertedUserID)
	if err != nil {
		h.logger.Error("failed to create user in database",
			zap.Error(err),
			zap.String("email", req.Email))
		h.tryDeleteWorkOSUser(c.Context(), workosUser.ID, "database failure")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user profile",
		})
	}

	// Then use insertedUserID for the doctors table insertion
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
		insertedUserID, // Use the ID generated by the database
		req.Name,
		req.IMRNumber,
		req.Age,
		specializationJSON,
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

// GetDoctorProfile retrieves a doctor's profile
func (h *DoctorAuthHandler) GetDoctorProfile(c *fiber.Ctx) error {
	// Get user ID from context (set by AuthMiddleware)
	authID, ok := c.Locals("authID").(string)
	if !ok {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User not authenticated",
		})
	}

	var userID uuid.UUID
	err := h.pgPool.QueryRow(c.Context(), "SELECT user_id FROM users WHERE auth_id = $1", authID).Scan(&userID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Get doctor from database
	var doctorProfile struct {
		UserID         uuid.UUID      `json:"user_id"`
		DoctorID       uuid.UUID      `json:"doctor_id"`
		AuthID         sql.NullString `json:"auth_id"`
		Name           sql.NullString `json:"name"`
		Email          sql.NullString `json:"email"`
		Mobile         int64          `json:"mobile"`
		BloodGroup     sql.NullString `json:"blood_group"`
		Location       sql.NullString `json:"location"`
		Address        sql.NullString `json:"address"`
		Username       sql.NullString `json:"username"`
		ProfilePic     sql.NullString `json:"profile_pic"`
		HospitalID     uuid.NullUUID  `json:"hospital_id"`
		AadhaarID      sql.NullString `json:"aadhaar_id"`
		IMRNumber      sql.NullString `json:"imr_number"`
		Age            sql.NullInt32  `json:"age"`
		Specialization sql.NullString `json:"specialization"`
		Qualification  sql.NullString `json:"qualification"`
		IsActive       bool           `json:"is_active"`
		SlotDuration   sql.NullInt32  `json:"slot_duration"`
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
			u.aadhaar_id,
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
		&doctorProfile.AadhaarID,
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

	// Convert NullXXX types to pointer types for JSON marshaling
	response := fiber.Map{
		"user_id":        doctorProfile.UserID,
		"doctor_id":      doctorProfile.DoctorID,
		"auth_id":        doctorProfile.AuthID,
		"name":           doctorProfile.Name,
		"specialization": doctorProfile.Specialization,
		"qualification":  doctorProfile.Qualification,
		"profile_pic":    doctorProfile.ProfilePic,
		"imr_number":     doctorProfile.IMRNumber,
		"age":            doctorProfile.Age,
		"slot_duration":  doctorProfile.SlotDuration,
		"blood_group":    doctorProfile.BloodGroup,
		"location":       doctorProfile.Location,
		"address":        doctorProfile.Address,
		"email":          doctorProfile.Email,
		"mobile":         doctorProfile.Mobile,
		"username":       doctorProfile.Username,
		"aadhaar_id":     doctorProfile.AadhaarID,
		"is_active":      doctorProfile.IsActive,
	}

	// Conditionally add fields that might be NULL
	if doctorProfile.BloodGroup.Valid {
		response["blood_group"] = doctorProfile.BloodGroup.String
	}

	if doctorProfile.Location.Valid {
		response["location"] = doctorProfile.Location.String
	}

	if doctorProfile.Address.Valid {
		response["address"] = doctorProfile.Address.String
	}

	if doctorProfile.ProfilePic.Valid {
		response["profile_pic"] = doctorProfile.ProfilePic.String
	}

	if doctorProfile.HospitalID.Valid {
		response["hospital_id"] = doctorProfile.HospitalID.UUID
	}

	if doctorProfile.IMRNumber.Valid {
		response["imr_number"] = doctorProfile.IMRNumber.String
	}

	if doctorProfile.Age.Valid {
		response["age"] = doctorProfile.Age.Int32
	}

	if doctorProfile.Specialization.Valid {
		response["specialization"] = doctorProfile.Specialization.String
	}

	if doctorProfile.Qualification.Valid {
		response["qualification"] = doctorProfile.Qualification.String
	}

	if doctorProfile.SlotDuration.Valid {
		response["slot_duration"] = doctorProfile.SlotDuration.Int32
	}

	return c.JSON(response)
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

// DoctorLogin handles doctor login
func (h *DoctorAuthHandler) DoctorLogin(c *fiber.Ctx) error {
	var req DoctorLoginRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.Error("failed to parse login request", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	// Get user ID from database
	var userID uuid.UUID
	var authID string
	err := h.pgPool.QueryRow(c.Context(),
		"SELECT user_id, auth_id FROM users WHERE email = $1",
		req.Email).Scan(&userID, &authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid email or password",
		})
	}

	// Verify password
	response, err := usermanagement.AuthenticateWithPassword(
		c.Context(),
		usermanagement.AuthenticateWithPasswordOpts{
			ClientID: h.config.WorkOSClientId,
			Email:    req.Email,
			Password: req.Password,
		},
	)
	// Prepare response
	loginResponse := map[string]interface{}{
		"access_token":  response.AccessToken,
		"refresh_token": response.RefreshToken,
		"user": map[string]interface{}{
			"id":         response.User.ID,
			"email":      response.User.Email,
			"first_name": response.User.FirstName,
			"last_name":  response.User.LastName,
		},
		"organization_id": response.OrganizationID,
	}

	h.logger.Info("login response", zap.Any("response", loginResponse))

	c.Locals("refresh_token", response.RefreshToken)

	if err != nil {
		h.logger.Error("failed to authenticate user", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid email or password",
		})
	}

	// Check if user is a doctor
	var isDoctor bool
	err = h.pgPool.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM doctors WHERE doctor_id = $1)",
		userID).Scan(&isDoctor)
	if err != nil {
		h.logger.Error("failed to check if user is a doctor", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	if !isDoctor {
		h.logger.Info("user is not a doctor", zap.String("email", req.Email))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User is not a doctor",
		})
	}

	// Generate session ID
	sessionID := uuid.New().String()

	// Save session in Redis
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	if err := h.redisClient.Set(c.Context(), sessionKey, authID, time.Hour*12).Err(); err != nil {
		h.logger.Error("failed to save session in Redis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create session",
		})
	}
	return c.JSON(fiber.Map{
		"message":    "Login successful",
		"session_id": sessionID,
	})
}
