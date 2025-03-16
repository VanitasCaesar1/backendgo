package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	_ "image/png" // Register PNG decoder
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/VanitasCaesar1/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
	"go.uber.org/zap"
)

type UserHandler struct {
	config         *config.Config
	redisClient    *redis.Client
	logger         *zap.Logger
	pgPool         *pgxpool.Pool
	minioClient    *minio.Client
	authMiddleware *middleware.AuthMiddleware // Added this field
}

type UserRegister struct {
	Email      string `json:"email"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Age        int    `json:"age"`
	MobileNo   string `json:"mobile_no"`
	BloodGroup string `json:"blood_group"`
	Location   string `json:"location"`
	Address    string `json:"address"`
	HospitalID string `json:"hospital_id"`
	AadhaarID  string `json:"aadhaar_id"`
}

type UserProfile struct {
	UserID        uuid.UUID  `json:"user_id"`
	AuthID        string     `json:"auth_id,omitempty"` // WorkOS user ID
	Username      string     `json:"username,omitempty"`
	ProfilePic    string     `json:"profile_pic,omitempty"`
	FirstName     string     `json:"first_name,omitempty"`
	LastName      string     `json:"last_name,omitempty"`
	Name          string     `json:"name,omitempty"`
	Mobile        string     `json:"mobile,omitempty"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified,omitempty"`
	BloodGroup    string     `json:"blood_group,omitempty"`
	Location      string     `json:"location,omitempty"`
	Address       string     `json:"address,omitempty"`
	HospitalID    *uuid.UUID `json:"hospital_id,omitempty"`
	AadhaarID     string     `json:"aadhaar_id,omitempty"`
	LastSignInAt  string     `json:"last_sign_in_at,omitempty"`
	CreatedAt     string     `json:"created_at,omitempty"`
	UpdatedAt     string     `json:"updated_at,omitempty"`
}

func NewUserHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, pgPool *pgxpool.Pool, authMiddleware *middleware.AuthMiddleware) (*UserHandler, error) {
	// Initialize Minio client
	minioClient, err := minio.New(cfg.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
		Secure: true,
		Region: "india-s-1",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize minio client: %w", err)
	}

	// Initialize WorkOS SDK
	usermanagement.SetAPIKey(cfg.WorkOSApiKey)

	return &UserHandler{
		config:         cfg,
		redisClient:    rds,
		logger:         logger,
		pgPool:         pgPool,
		minioClient:    minioClient,
		authMiddleware: authMiddleware, // Initialize the field
	}, nil
}

// RegisterRoutes registers user-related routes
func (h *UserHandler) RegisterUser(c *fiber.Ctx) error {
	// Parse request body
	var req UserRegister
	if err := c.BodyParser(&req); err != nil {
		h.logger.Error("failed to parse register request", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request data",
		})
	}

	// Validate the registration request
	if err := h.validateRegister(c, &req); err != nil {
		// validateRegister method should have already set the appropriate status and error response
		return err
	}

	// Check for existing users
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

	// Check for existing email, username, and Aadhaar ID
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

	// Create user in WorkOS
	workosUser, err := usermanagement.CreateUser(
		c.Context(),
		usermanagement.CreateUserOpts{
			Email:         req.Email,
			FirstName:     req.FirstName,
			LastName:      req.LastName,
			Password:      req.Password,
			EmailVerified: true,
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
	h.logger.Debug("processing registration request",
		zap.String("email", req.Email),
		zap.String("username", req.Username))
	// Add this to your validateRegister function in the Go code
	if req.AadhaarID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Aadhaar ID is required",
		})
	}

	// Start transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	defer tx.Rollback(c.Context()) // Rollback if not committed

	// Insert user into database - let the database generate the UUID
	var userId uuid.UUID
	err = tx.QueryRow(c.Context(),
		`INSERT INTO users (auth_id, email, name, age, mobile, blood_group, location, address, aadhaar_id, username)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING user_id`,
		workosUser.ID, req.Email, req.FirstName+" "+req.LastName, req.Age, req.MobileNo,
		req.BloodGroup, req.Location, req.Address, req.AadhaarID, req.Username).Scan(&userId)

	if err != nil {
		h.logger.Error("failed to create user in database", zap.Error(err))
		h.tryDeleteWorkOSUser(c.Context(), workosUser.ID, "database insertion failure")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user account",
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

	// Log successful user creation
	h.logger.Info("new user created",
		zap.String("user_id", userId.String()),
		zap.String("auth_id", workosUser.ID))

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "User registered successfully",
		"user_id": userId.String(), // Convert UUID to string for JSON
	})
}

// tryDeleteWorkOSUser centralizes WorkOS user deletion to reduce code duplication
func (h *UserHandler) tryDeleteWorkOSUser(c context.Context, workosUserID string, reason string) {
	if err := usermanagement.DeleteUser(
		c,
		usermanagement.DeleteUserOpts{
			User: workosUserID,
		},
	); err != nil {
		h.logger.Error("failed to delete WorkOS user after "+reason,
			zap.Error(err),
			zap.String("workos_id", workosUserID))
	}
}

func (h *UserHandler) validateRegister(c *fiber.Ctx, register *UserRegister) error {

	if register.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email is required",
		})
	}

	if register.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Password is required",
		})
	}

	if register.Age < 18 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Age must be 18 or above",
		})
	}

	if register.MobileNo != "" {
		// Basic mobile number validation - adjust pattern as needed
		mobilePattern := regexp.MustCompile(`^\+?[0-9]{10,15}$`)
		if !mobilePattern.MatchString(register.MobileNo) {
			h.logger.Error("invalid mobile number format",
				zap.String("mobile", register.MobileNo))
			return errors.New("invalid mobile number format")
		}

		// Verify it can be parsed as a number since it's stored as numeric in DB
		if _, err := strconv.ParseFloat(register.MobileNo, 64); err != nil {
			h.logger.Error("mobile not numeric",
				zap.String("mobile", register.MobileNo),
				zap.Error(err))
			return errors.New("mobile number must be numeric")
		}
	}

	if register.BloodGroup != "" {
		validBloodGroups := map[string]bool{
			"A+": true, "A-": true,
			"B+": true, "B-": true,
			"O+": true, "O-": true,
			"AB+": true, "AB-": true,
		}
		if !validBloodGroups[register.BloodGroup] {
			h.logger.Error("invalid blood group",
				zap.String("blood_group", register.BloodGroup))
			return errors.New("invalid blood group")
		}
	}

	if register.Location == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Location is required",
		})
	}

	if register.Address == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Address is required",
		})
	}

	if register.HospitalID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Hospital ID is required",
		})
	}

	if register.AadhaarID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Aadhaar ID is required",
		})
	}
	// In your Go validateRegister function
	aadhaarIDStr := register.AadhaarID
	h.logger.Debug("Validating Aadhaar ID",
		zap.String("aadhaar_id", aadhaarIDStr),
		zap.Int("length", len(aadhaarIDStr)),
		zap.Bool("regex_match", regexp.MustCompile(`^\d{12}$`).MatchString(aadhaarIDStr)))
	return nil
}

// GetUserProfile retrieves the user's profile
func (h *UserHandler) GetUserProfile(c *fiber.Ctx) error {
	// Get WorkOS user ID from context
	authID, ok := c.Locals("authID").(string)
	if !ok {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User ID not found",
		})
	}

	h.logger.Info("processing user profile request",
		zap.String("authID", authID),
		zap.Any("all_claims", c.Locals("claims")),
	)

	// Get user from WorkOS
	workosUser, err := usermanagement.GetUser(
		c.Context(),
		usermanagement.GetUserOpts{
			User: authID,
		},
	)
	if err != nil {
		h.logger.Error("failed to fetch user from WorkOS", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user profile from authentication provider",
		})
	}

	// Check if user exists in our database
	var exists bool
	err = h.pgPool.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM users WHERE auth_id = $1)",
		authID).Scan(&exists)
	if err != nil {
		h.logger.Error("failed to check user existence", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	var userID uuid.UUID

	// Use a separate transaction for creating user if needed
	if !exists {
		// Create a transaction specifically for user creation
		tx, err := h.pgPool.Begin(c.Context())
		if err != nil {
			h.logger.Error("failed to begin transaction for user creation", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database error",
			})
		}
		defer tx.Rollback(c.Context()) // Rollback if not committed

		// Create new user in our database
		userID = uuid.New()
		_, err = tx.Exec(c.Context(),
			`INSERT INTO users (user_id, auth_id, email, name, profile_pic) 
			 VALUES ($1, $2, $3, $4, $5)`,
			userID, authID, workosUser.Email,
			strings.TrimSpace(workosUser.FirstName+" "+workosUser.LastName),
			workosUser.ProfilePictureURL,
		)
		if err != nil {
			h.logger.Error("failed to create user",
				zap.Error(err),
				zap.String("userID", userID.String()),
				zap.String("authID", authID),
				zap.String("email", workosUser.Email))

			// Check for unique constraint violations
			if strings.Contains(err.Error(), "unique constraint") {
				if strings.Contains(err.Error(), "users_email_key") {
					return c.Status(fiber.StatusConflict).JSON(fiber.Map{
						"error": "Email already registered",
					})
				} else if strings.Contains(err.Error(), "users_username_key") {
					return c.Status(fiber.StatusConflict).JSON(fiber.Map{
						"error": "Username already taken",
					})
				} else if strings.Contains(err.Error(), "users_mobile_key") {
					return c.Status(fiber.StatusConflict).JSON(fiber.Map{
						"error": "Mobile number already registered",
					})
				}
			}

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create user profile",
			})
		}

		// Commit the transaction for user creation
		if err := tx.Commit(c.Context()); err != nil {
			h.logger.Error("failed to commit transaction for user creation", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database error during user creation",
			})
		}

		h.logger.Info("new user created",
			zap.String("userID", userID.String()),
			zap.String("authID", authID))
	} else {
		// Get existing user ID
		err = h.pgPool.QueryRow(c.Context(),
			"SELECT user_id FROM users WHERE auth_id = $1",
			authID).Scan(&userID)
		if err != nil {
			h.logger.Error("failed to get user ID", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database error",
			})
		}
	}

	// Use a separate transaction for updating WorkOS data
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction for updating WorkOS data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	defer tx.Rollback(c.Context()) // Rollback if not committed

	// Update user profile with latest WorkOS data
	fullName := strings.TrimSpace(workosUser.FirstName + " " + workosUser.LastName)

	_, err = tx.Exec(c.Context(),
		`UPDATE users 
		 SET email = $1, 
			 name = $2, 
			 profile_pic = $3
		 WHERE auth_id = $4`,
		workosUser.Email, fullName,
		workosUser.ProfilePictureURL, authID)
	if err != nil {
		h.logger.Error("failed to update user with WorkOS data",
			zap.Error(err),
			zap.String("authID", authID))
		// Continue anyway - we can still try to fetch the profile
	} else {
		// Only commit if update was successful
		if err := tx.Commit(c.Context()); err != nil {
			h.logger.Error("failed to commit transaction for updating WorkOS data", zap.Error(err))
			// Continue anyway - we can still try to fetch the profile
		}
	}

	// Get additional profile data from our database using a direct query, not a transaction
	var profile UserProfile
	var mobileStr sql.NullString
	err = h.pgPool.QueryRow(c.Context(),
		`SELECT 
			user_id,
			auth_id,
			COALESCE(username, '') as username,
			COALESCE(profile_pic, '') as profile_pic,
			COALESCE(name, '') as name,
			COALESCE(CAST(mobile AS TEXT), '') as mobile,
			COALESCE(email, $2) as email,
			COALESCE(blood_group, '') as blood_group,
			COALESCE(location, '') as location,
			COALESCE(address, '') as address,
			hospital_id,
			COALESCE(aadhaar_id, '') as aadhaar_id
		FROM users 
		WHERE auth_id = $1`,
		authID, workosUser.Email).Scan(
		&profile.UserID,
		&profile.AuthID,
		&profile.Username,
		&profile.ProfilePic,
		&profile.Name,
		&mobileStr,
		&profile.Email,
		&profile.BloodGroup,
		&profile.Location,
		&profile.Address,
		&profile.HospitalID,
		&profile.AadhaarID,
	)

	if err != nil {
		h.logger.Error("failed to fetch user profile", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user profile",
		})
	}

	// Convert mobile from string to the format needed for response
	if mobileStr.Valid {
		profile.Mobile = mobileStr.String
	}

	// Merge WorkOS data with our database data
	profile.LastSignInAt = workosUser.LastSignInAt
	profile.CreatedAt = workosUser.CreatedAt
	profile.UpdatedAt = workosUser.UpdatedAt

	// Set FirstName and LastName from WorkOS for the response
	profile.FirstName = workosUser.FirstName
	profile.LastName = workosUser.LastName
	profile.EmailVerified = workosUser.EmailVerified

	return c.JSON(profile)
}

// UpdateUserProfile updates the user's profile information
func (h *UserHandler) UpdateUserProfile(c *fiber.Ctx) error {
	authID, ok := c.Locals("authID").(string)
	if !ok {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User ID not found",
		})
	}

	var updateData UserProfile
	if err := c.BodyParser(&updateData); err != nil {
		h.logger.Error("failed to parse update data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request data",
		})
	}

	if err := h.validateProfileUpdate(&updateData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Start transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	defer tx.Rollback(c.Context()) // Rollback if not committed

	// First check if user exists
	var exists bool
	err = tx.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM users WHERE auth_id = $1)",
		authID).Scan(&exists)
	if err != nil {
		h.logger.Error("failed to check user existence",
			zap.Error(err),
			zap.String("auth_id", authID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User profile not found",
		})
	}

	// Check if username is unique if it was provided
	if updateData.Username != "" {
		var usernameExists bool
		err = tx.QueryRow(c.Context(),
			"SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND auth_id != $2)",
			updateData.Username, authID).Scan(&usernameExists)
		if err != nil {
			h.logger.Error("failed to check username uniqueness",
				zap.Error(err),
				zap.String("username", updateData.Username))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Database error",
			})
		}

		if usernameExists {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "Username already taken",
			})
		}
	}

	// Convert mobile string to numeric for DB if provided
	var mobileVal interface{} = nil
	if updateData.Mobile != "" {
		// Verify mobile is numeric before attempting conversion
		if _, err := strconv.ParseFloat(updateData.Mobile, 64); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Mobile number must be numeric",
			})
		}
		mobileVal = updateData.Mobile
	}

	// Validate Aadhaar ID if provided
	if updateData.AadhaarID != "" && !regexp.MustCompile(`^\d{12}$`).MatchString(updateData.AadhaarID) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Aadhaar ID must be 12 digits",
		})
	}

	// Update in our database
	commandTag, err := tx.Exec(c.Context(),
		`UPDATE users 
     SET username = $1, 
         name = $2, 
         mobile = $3, 
         blood_group = $4, 
         location = $5, 
         address = $6,
         hospital_id = $7,
         aadhaar_id = $8
     WHERE auth_id = $9`,
		updateData.Username,
		updateData.Name,
		mobileVal,
		updateData.BloodGroup,
		updateData.Location,
		updateData.Address,
		updateData.HospitalID,
		updateData.AadhaarID,
		authID,
	)

	if err != nil {
		h.logger.Error("failed to update user profile",
			zap.Error(err),
			zap.String("auth_id", authID))

		// Check for foreign key violations
		if strings.Contains(err.Error(), "violates foreign key constraint") &&
			strings.Contains(err.Error(), "fk_references_hosp_id") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid hospital ID provided",
			})
		}

		// Check for Aadhaar validation errors
		if strings.Contains(err.Error(), "violates check constraint \"valid_aadhaar\"") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Aadhaar ID must be exactly 12 digits",
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update profile",
		})
	}

	if commandTag.RowsAffected() != 1 {
		h.logger.Error("no rows affected during update",
			zap.String("auth_id", authID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update profile",
		})
	}

	// Update first/last name in WorkOS if provided
	if updateData.FirstName != "" || updateData.LastName != "" {
		updateOpts := usermanagement.UpdateUserOpts{
			User: authID,
		}
		if updateData.FirstName != "" {
			updateOpts.FirstName = updateData.FirstName
		}
		if updateData.LastName != "" {
			updateOpts.LastName = updateData.LastName
		}

		_, err = usermanagement.UpdateUser(
			c.Context(),
			updateOpts,
		)
		if err != nil {
			h.logger.Error("failed to update user in WorkOS",
				zap.Error(err),
				zap.String("auth_id", authID))
			// Continue anyway - the local update was successful
		}
	}

	// Commit transaction
	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Profile updated successfully",
	})
}

func (h *UserHandler) validateProfileUpdate(profile *UserProfile) error {
	// Username validation
	if profile.Username != "" {
		if len(profile.Username) < 3 || len(profile.Username) > 30 {
			h.logger.Error("invalid username length",
				zap.String("username", profile.Username),
				zap.Int("length", len(profile.Username)))
			return errors.New("username must be between 3 and 30 characters")
		}

		// Only allow alphanumeric characters, underscores, and periods
		usernamePattern := regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)
		if !usernamePattern.MatchString(profile.Username) {
			h.logger.Error("invalid username format",
				zap.String("username", profile.Username))
			return errors.New("username can only contain letters, numbers, underscores, and periods")
		}
	}

	// Name validation
	if len(profile.Name) > 100 {
		h.logger.Error("name too long",
			zap.String("name", profile.Name))
		return errors.New("name must not exceed 100 characters")
	}

	// First name validation
	if len(profile.FirstName) > 50 {
		h.logger.Error("first name too long",
			zap.String("first_name", profile.FirstName))
		return errors.New("first name must not exceed 50 characters")
	}

	// Last name validation
	if len(profile.LastName) > 50 {
		h.logger.Error("last name too long",
			zap.String("last_name", profile.LastName))
		return errors.New("last name must not exceed 50 characters")
	}

	// Mobile number validation
	if profile.Mobile != "" {
		// Basic mobile number validation - adjust pattern as needed
		mobilePattern := regexp.MustCompile(`^\+?[0-9]{10,15}$`)
		if !mobilePattern.MatchString(profile.Mobile) {
			h.logger.Error("invalid mobile number format",
				zap.String("mobile", profile.Mobile))
			return errors.New("invalid mobile number format")
		}

		// Verify it can be parsed as a number since it's stored as numeric in DB
		if _, err := strconv.ParseFloat(profile.Mobile, 64); err != nil {
			h.logger.Error("mobile not numeric",
				zap.String("mobile", profile.Mobile),
				zap.Error(err))
			return errors.New("mobile number must be numeric")
		}
	}

	// Blood group validation
	if profile.BloodGroup != "" {
		validBloodGroups := map[string]bool{
			"A+": true, "A-": true,
			"B+": true, "B-": true,
			"O+": true, "O-": true,
			"AB+": true, "AB-": true,
		}
		if !validBloodGroups[profile.BloodGroup] {
			h.logger.Error("invalid blood group",
				zap.String("blood_group", profile.BloodGroup))
			return errors.New("invalid blood group")
		}
	}

	// Location validation
	if len(profile.Location) > 100 {
		h.logger.Error("location too long",
			zap.String("location", profile.Location))
		return errors.New("location must not exceed 100 characters")
	}

	// Address validation
	if len(profile.Address) > 500 {
		h.logger.Error("address too long",
			zap.String("address", profile.Address))
		return errors.New("address must not exceed 500 characters")
	}

	return nil
}

// Password Reset Token Generator
func (h *UserHandler) ResetPassword(c *fiber.Ctx) error {
	// Path matching should be based on the relative path or route pattern
	// rather than comparing to full path directly

	// Get the last part of the path
	pathSegments := strings.Split(c.Path(), "/")
	lastSegment := pathSegments[len(pathSegments)-1]

	// 1. Request a password reset token (only needs email)
	if lastSegment == "request-reset" {
		var requestBody struct {
			Email string `json:"email"`
		}
		if err := c.BodyParser(&requestBody); err != nil {
			h.logger.Error("failed to parse request body", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		// Generate password reset token
		response, err := usermanagement.CreatePasswordReset(
			context.Background(),
			usermanagement.CreatePasswordResetOpts{
				Email: requestBody.Email,
			},
		)
		if err != nil {
			h.logger.Error("failed to generate password reset token",
				zap.Error(err),
				zap.String("email", requestBody.Email))
			// Still return success for security (don't reveal if email exists)
			return c.JSON(fiber.Map{
				"message": "If this email exists, a password reset link has been sent",
			})
		}

		// Here you would send an email with the reset link
		// For development, you could log the token or URL
		h.logger.Info("password reset token generated",
			zap.String("resetURL", response.PasswordResetUrl))
		return c.JSON(fiber.Map{
			"message": "If this email exists, a password reset link has been sent",
		})
	}

	// 2. Apply the password reset (needs token and new password)
	if lastSegment == "reset-password" {
		var requestBody struct {
			Token       string `json:"token"`
			NewPassword string `json:"newPassword"`
		}
		if err := c.BodyParser(&requestBody); err != nil {
			h.logger.Error("failed to parse request body", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}
		if requestBody.Token == "" || requestBody.NewPassword == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Token and new password are required",
			})
		}

		// Reset password using the token
		user, err := usermanagement.ResetPassword(
			context.Background(),
			usermanagement.ResetPasswordOpts{
				Token:       requestBody.Token,
				NewPassword: requestBody.NewPassword,
			},
		)
		if err != nil {
			h.logger.Error("failed to reset password", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}
		h.logger.Info("password reset successful",
			zap.String("userId", user.User.ID))
		return c.JSON(fiber.Map{
			"message": "Password reset successfully",
		})
	}

	// 3. Validate a token (optional, if you want to check token validity)
	if lastSegment == "validate-reset-token" {
		token := c.Query("token")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Token is required",
			})
		}

		// Use GetPasswordReset to validate token
		// Note: WorkOS doesn't have a direct validate token method
		// so we need to improvise by fetching reset details
		response, err := usermanagement.GetPasswordReset(
			context.Background(),
			usermanagement.GetPasswordResetOpts{
				PasswordReset: token, // Note: This should be the reset ID, not token
			},
		)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"valid": false,
				"error": "Invalid token",
			})
		}

		// Check if token is expired
		// Parse the expires_at time
		expiresAt, err := time.Parse(time.RFC3339, response.ExpiresAt)
		if err != nil || time.Now().After(expiresAt) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"valid": false,
				"error": "Token expired",
			})
		}
		return c.JSON(fiber.Map{
			"valid": true,
		})
	}

	// If none of the paths match
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
		"error": "Endpoint not found",
	})
}
