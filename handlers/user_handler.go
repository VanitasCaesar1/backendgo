package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png" // Register PNG decoder
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/nfnt/resize"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	maxFileSize  = 5 * 1024 * 1024 // 5MB
	bucketName   = "profile-pics"
	maxDimension = 500 // Maximum width/height for profile pictures
	jpegQuality  = 85  // JPEG compression quality
)

type UserHandler struct {
	config      *config.Config
	redisClient *redis.Client
	logger      *zap.Logger
	authHandler *AuthHandler
	pgPool      *pgxpool.Pool
	minioClient *minio.Client
}

type UserProfile struct {
	KeycloakID uuid.UUID `json:"keycloak_id"`
	Username   string    `json:"username,omitempty"`
	ProfilePic string    `json:"profile_pic,omitempty"`
	Name       string    `json:"name"`
	Mobile     string    `json:"mobile"`
	Email      string    `json:"email"`
	BloodGroup string    `json:"blood_group,omitempty"`
	Location   string    `json:"location,omitempty"`
	Address    string    `json:"address,omitempty"`
}

func NewUserHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, auth *AuthHandler, pgPool *pgxpool.Pool) (*UserHandler, error) {
	// Initialize Minio client
	minioClient, err := minio.New(cfg.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
		Secure: true,
		Region: "india-s-1",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize minio client: %w", err)
	}

	return &UserHandler{
		config:      cfg,
		redisClient: rds,
		logger:      logger,
		authHandler: auth,
		pgPool:      pgPool,
		minioClient: minioClient,
	}, nil
}

// GetUserProfile retrieves the user's profile
func (h *UserHandler) GetUserProfile(c *fiber.Ctx) error {
	userID, ok := c.Locals("userID").(string)
	if !ok {
		h.logger.Error("userID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User ID not found",
		})
	}

	email, ok := c.Locals("email").(string)
	if !ok {
		h.logger.Error("email not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Email not found",
		})
	}

	h.logger.Info("processing user profile request",
		zap.String("userID", userID),
		zap.String("email", email),
		zap.Any("all_claims", c.Locals("claims")),
	)

	keycloakID, err := uuid.Parse(userID)
	if err != nil {
		h.logger.Error("invalid keycloak ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
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

	var profile UserProfile
	err = tx.QueryRow(c.Context(),
		`SELECT 
			keycloak_id,
			COALESCE(username, '') as username,
			COALESCE(profile_pic, '') as profile_pic,
			COALESCE(name, '') as name,
			COALESCE(CAST(mobile AS TEXT), '') as mobile,
			COALESCE(email, $2) as email,
			COALESCE(blood_group, '') as blood_group,
			COALESCE(location, '') as location,
			COALESCE(address, '') as address
		FROM users 
		WHERE keycloak_id = $1`,
		keycloakID, email).Scan(
		&profile.KeycloakID,
		&profile.Username,
		&profile.ProfilePic,
		&profile.Name,
		&profile.Mobile,
		&profile.Email,
		&profile.BloodGroup,
		&profile.Location,
		&profile.Address,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			profile = UserProfile{
				KeycloakID: keycloakID,
				Email:      email,
			}

			commandTag, err := tx.Exec(c.Context(),
				`INSERT INTO users (keycloak_id, email) VALUES ($1, $2)`,
				keycloakID, email)
			if err != nil {
				h.logger.Error("failed to create user profile",
					zap.Error(err),
					zap.String("keycloakID", keycloakID.String()))
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to create user profile",
				})
			}

			if commandTag.RowsAffected() != 1 {
				h.logger.Error("failed to insert user profile - no rows affected",
					zap.String("keycloakID", keycloakID.String()))
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to create user profile",
				})
			}

			h.logger.Info("new user profile created successfully",
				zap.String("keycloakID", keycloakID.String()))
		} else {
			h.logger.Error("failed to fetch user profile",
				zap.Error(err),
				zap.String("keycloakID", keycloakID.String()))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch user profile",
			})
		}
	}

	// Commit transaction
	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	return c.JSON(profile)
}

// UpdateUserProfile updates the user's profile information
func (h *UserHandler) UpdateUserProfile(c *fiber.Ctx) error {
	userID, ok := c.Locals("userID").(string)
	if !ok {
		h.logger.Error("userID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User ID not found",
		})
	}

	keycloakID, err := uuid.Parse(userID)
	if err != nil {
		h.logger.Error("invalid keycloak ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID format",
		})
	}

	var updateData UserProfile
	if err := c.BodyParser(&updateData); err != nil {
		h.logger.Error("failed to parse update data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request data",
		})
	}

	contextEmail, ok := c.Locals("email").(string)
	if !ok {
		h.logger.Error("email not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Email not found",
		})
	}

	updateData.Email = contextEmail

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
		"SELECT EXISTS(SELECT 1 FROM users WHERE keycloak_id = $1)",
		keycloakID).Scan(&exists)
	if err != nil {
		h.logger.Error("failed to check user existence",
			zap.Error(err),
			zap.String("keycloak_id", keycloakID.String()))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}

	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User profile not found",
		})
	}

	// Perform update within transaction
	commandTag, err := tx.Exec(c.Context(),
		`UPDATE users 
		 SET name = $1, mobile = $2, blood_group = $3, 
		     location = $4, address = $5
		 WHERE keycloak_id = $6`,
		updateData.Name,
		updateData.Mobile,
		updateData.BloodGroup,
		updateData.Location,
		updateData.Address,
		keycloakID,
	)

	if err != nil {
		h.logger.Error("failed to update user profile",
			zap.Error(err),
			zap.String("keycloak_id", keycloakID.String()))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update profile",
		})
	}

	if commandTag.RowsAffected() != 1 {
		h.logger.Error("no rows affected during update",
			zap.String("keycloak_id", keycloakID.String()))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update profile",
		})
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
	// Name validation
	if len(profile.Name) > 100 {
		h.logger.Error("name too long",
			zap.String("name", profile.Name))
		return errors.New("name must not exceed 100 characters")
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

func (h *UserHandler) testMinioConnection(ctx context.Context) error {
	_, err := h.minioClient.ListBuckets(ctx)
	if err != nil {
		if err.Error() == "Found" {
			// "Found" indicates a successful connection
			return nil
		}
		h.logger.Error("failed to connect to minio",
			zap.Error(err),
			zap.String("endpoint", h.config.MinioEndpoint))
		return err
	}
	return nil
}

func (h *UserHandler) UploadProfilePic(c *fiber.Ctx) error {
	// Get user ID from context
	userID, ok := c.Locals("userID").(string)
	if !ok {
		h.logger.Error("userID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User ID not found",
		})
	}

	if err := h.testMinioConnection(context.Background()); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Storage service unavailable",
		})
	}
	// Parse multipart form
	file, err := c.FormFile("profilePic")
	if err != nil {
		h.logger.Error("failed to get file from form", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "No file uploaded",
		})
	}

	// Validate file size
	if file.Size > maxFileSize {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("File size exceeds maximum limit of %d MB", maxFileSize/(1024*1024)),
		})
	}

	// Validate file type
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Only JPG and PNG files are allowed",
		})
	}

	// Open the uploaded file
	src, err := file.Open()
	if err != nil {
		h.logger.Error("failed to open uploaded file", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process uploaded file",
		})
	}
	defer src.Close()

	// Decode image
	img, _, err := image.Decode(src)
	if err != nil {
		h.logger.Error("failed to decode image", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid image format",
		})
	}

	// Resize image to 512x512
	resized := resize.Resize(512, 512, img, resize.Lanczos3)

	// Convert to JPEG and compress
	buf := new(bytes.Buffer)
	if err := jpeg.Encode(buf, resized, &jpeg.Options{Quality: jpegQuality}); err != nil {
		h.logger.Error("failed to encode image", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process image",
		})
	}

	// Generate unique filename
	filename := fmt.Sprintf("%s.jpg", uuid.New().String())

	// Create a context with timeout for MinIO operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if bucket exists, create if it doesn't
	exists, err := h.minioClient.BucketExists(ctx, bucketName)
	h.logger.Info("bucket status",
		zap.String("bucket", bucketName),
		zap.Bool("exists", exists),
		zap.Error(err))

	if err != nil && err.Error() != "Found" {
		h.logger.Error("failed to check bucket existence",
			zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to check storage configuration",
		})
	}

	// Only try to create bucket if it doesn't exist and we didn't get a "Found" error
	if !exists && err == nil {
		err = h.minioClient.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{
			Region: "india-s-1",
		})
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			h.logger.Error("failed to create bucket", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to configure storage",
			})
		}
	}

	// Upload to MinIO with proper content length and type
	info, err := h.minioClient.PutObject(
		ctx,
		bucketName,
		filename,
		bytes.NewReader(buf.Bytes()),
		int64(buf.Len()),
		minio.PutObjectOptions{
			ContentType: "image/jpeg",
		},
	)

	if err != nil {
		h.logger.Error("failed to upload to minio",
			zap.Error(err),
			zap.String("bucketName", bucketName),
			zap.String("filename", filename))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to store image",
		})
	}

	// Verify upload was successful
	if info.Size == 0 {
		h.logger.Error("upload completed but file size is 0",
			zap.String("filename", filename))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to store image properly",
		})
	}

	_, err = h.minioClient.StatObject(ctx, bucketName, filename, minio.StatObjectOptions{})
	if err != nil {
		h.logger.Error("failed to verify uploaded object",
			zap.Error(err),
			zap.String("filename", filename))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to verify uploaded image",
		})
	}

	h.logger.Info("successfully uploaded file to minio",
		zap.String("bucket", bucketName),
		zap.String("filename", filename),
		zap.Any("info", info),
	)

	// Update user profile in database
	if err := h.updateProfilePicURL(c.Context(), userID, filename); err != nil {
		h.logger.Error("failed to update profile pic URL", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update profile picture",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Profile picture updated successfully",
		"url":     filename,
	})
}

func (h *UserHandler) updateProfilePicURL(ctx context.Context, userID string, filename string) error {
	keycloakID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	_, err = h.pgPool.Exec(ctx,
		"UPDATE users SET profile_pic = $1 WHERE keycloak_id = $2",
		filename, keycloakID)
	return err
}

// Add this to your user_handler.go file
// GetProfilePic retrieves a profile picture from MinIO
func (h *UserHandler) GetProfilePic(c *fiber.Ctx) error {
	filename := c.Params("filename")

	// Basic validation to prevent path traversal
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid filename",
		})
	}

	// Increase timeout for image retrieval
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// test
	// Add retry mechanism for MinIO connection
	var obj *minio.Object
	var err error

	// Try up to 3 times with exponential backoff
	for attempt := 0; attempt < 3; attempt++ {
		obj, err = h.minioClient.GetObject(ctx, bucketName, filename, minio.GetObjectOptions{})
		if err == nil {
			break
		}

		h.logger.Warn("attempt to get object from minio failed, retrying...",
			zap.Error(err),
			zap.String("filename", filename),
			zap.Int("attempt", attempt+1))

		// Don't sleep on the last attempt
		if attempt < 2 {
			time.Sleep(time.Duration(100*(2<<attempt)) * time.Millisecond)
		}
	}

	if err != nil {
		h.logger.Error("all attempts to get object from minio failed",
			zap.Error(err),
			zap.String("filename", filename))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve image",
		})
	}

	// Get object info to set content-type with retry
	var objInfo minio.ObjectInfo
	for attempt := 0; attempt < 3; attempt++ {
		objInfo, err = obj.Stat()
		if err == nil {
			break
		}

		h.logger.Warn("attempt to get object stats failed, retrying...",
			zap.Error(err),
			zap.String("filename", filename),
			zap.Int("attempt", attempt+1))

		// Don't sleep on the last attempt
		if attempt < 2 {
			time.Sleep(time.Duration(100*(2<<attempt)) * time.Millisecond)
		}
	}

	if err != nil {
		h.logger.Error("all attempts to get object stats failed",
			zap.Error(err),
			zap.String("filename", filename))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Image not found",
		})
	}

	// Set appropriate headers
	c.Set("Content-Type", objInfo.ContentType)
	c.Set("Content-Length", fmt.Sprintf("%d", objInfo.Size))
	c.Set("Cache-Control", "public, max-age=86400") // Cache for 24 hours
	c.Set("ETag", objInfo.ETag)

	// Stream the file to the client with a more robust approach
	buffer := make([]byte, 32*1024) // 32KB buffer
	_, err = io.CopyBuffer(c, obj, buffer)
	if err != nil {
		h.logger.Error("failed to stream file to client",
			zap.Error(err),
			zap.String("filename", filename))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to stream image data",
		})
	}

	return nil
}
