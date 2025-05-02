package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"mime/multipart"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/nfnt/resize"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/organizations"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/zap"
)

type HospitalHandler struct {
	config      *config.Config
	redisClient *redis.Client
	logger      *zap.Logger
	mongoClient *mongo.Client
	pgPool      *pgxpool.Pool
	minioClient *minio.Client
}

type HospitalFee struct {
	ID        uuid.UUID `json:"id,omitempty"`
	FeeType   string    `json:"fee_type"`
	Amount    float64   `json:"amount"`
	CreatedAt string    `json:"created_at,omitempty"`
}

type Hospital struct {
	ID            uuid.UUID     `json:"id,omitempty"`
	AdminID       uuid.UUID     `json:"admin_id"`
	OrgID         string        `json:"org_id"`
	Name          string        `json:"name"`
	Email         string        `json:"email"`
	Number        int64         `json:"number"`
	Address       string        `json:"address"`
	LicenseNumber string        `json:"license_number,omitempty"`
	StartTime     string        `json:"startTime" validate:"required"` // Time as string HH:MM:SS
	EndTime       string        `json:"endTime" validate:"required"`   //
	Location      string        `json:"location"`
	Speciality    string        `json:"speciality,omitempty"`
	CreatedAt     string        `json:"created_at,omitempty"`
	Fees          []HospitalFee `json:"fees,omitempty"`
	HospitalPics  []string      `json:"hospital_pics,omitempty"` // Changed to []string for URLs only
}

func NewHospitalHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, mongoClient *mongo.Client, pgPool *pgxpool.Pool) (*HospitalHandler, error) {
	minioClient, err := minio.New(cfg.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
		Secure: true,
		Region: "india-s-1",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize minio client: %w", err)
	}

	organizations.SetAPIKey(cfg.WorkOSApiKey)
	return &HospitalHandler{
		config:      cfg,
		redisClient: rds,
		logger:      logger,
		mongoClient: mongoClient,
		pgPool:      pgPool,
		minioClient: minioClient,
	}, nil
}

// Helper functions
func (h *HospitalHandler) getUserID(ctx context.Context, authID string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := h.pgPool.QueryRow(ctx, "SELECT user_id FROM users WHERE auth_id = $1", authID).Scan(&userID)
	return userID, err
}

func (h *HospitalHandler) getAuthID(c *fiber.Ctx) (string, error) {
	authID, ok := c.Locals("authID").(string)
	if !ok {
		return "", errors.New("user ID not found")
	}
	return authID, nil
}

// UploadHospitalImages handles uploading multiple hospital images to MinIO
// and storing references in MongoDB
func (h *HospitalHandler) UploadHospitalImages(c *fiber.Ctx, hospitalID, organizationID string) ([]string, error) {
	// Get form files
	form, err := c.MultipartForm()
	if err != nil {
		h.logger.Error("failed to get multipart form", zap.Error(err))
		return nil, fiber.NewError(fiber.StatusBadRequest, "No files uploaded")
	}

	files := form.File["hospitalPics"]
	if len(files) == 0 {
		return []string{}, nil // Return empty array if no files uploaded
	}

	if err := h.testMinioConnection(context.Background()); err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Storage service unavailable")
	}

	// Bucket for hospital pictures
	const hospitalBucketName = "hospital-pics"
	const maxHospitalFileSize = 10 * 1024 * 1024 // 10MB
	const jpegQuality = 85

	// Create a context with timeout for MinIO operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if bucket exists, create if it doesn't
	exists, err := h.minioClient.BucketExists(ctx, hospitalBucketName)
	h.logger.Info("bucket status",
		zap.String("bucket", hospitalBucketName),
		zap.Bool("exists", exists),
		zap.Error(err))

	if err != nil && err.Error() != "Found" {
		h.logger.Error("failed to check bucket existence", zap.Error(err))
		return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to check storage configuration")
	}

	// Only try to create bucket if it doesn't exist and we didn't get a "Found" error
	if !exists && err == nil {
		err = h.minioClient.MakeBucket(ctx, hospitalBucketName, minio.MakeBucketOptions{
			Region: "india-s-1",
		})
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			h.logger.Error("failed to create bucket", zap.Error(err))
			return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to configure storage")
		}
	}

	// Store only filenames instead of full URLs
	filenames := make([]string, 0, len(files))
	mongoImageDocs := make([]interface{}, 0, len(files))

	// Process each file
	for _, file := range files {
		// Validate file size
		if file.Size > maxHospitalFileSize {
			return nil, fiber.NewError(fiber.StatusBadRequest,
				fmt.Sprintf("File size exceeds maximum limit of %d MB", maxHospitalFileSize/(1024*1024)))
		}

		// Validate file type
		ext := strings.ToLower(filepath.Ext(file.Filename))
		if ext != ".jpg" && ext != ".jpeg" && ext != ".png" {
			return nil, fiber.NewError(fiber.StatusBadRequest, "Only JPG and PNG files are allowed")
		}

		// Open the uploaded file
		src, err := file.Open()
		if err != nil {
			h.logger.Error("failed to open uploaded file", zap.Error(err))
			return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to process uploaded file")
		}

		// Use defer in a closure to ensure file is closed after processing
		func(src multipart.File) {
			defer src.Close()

			// Decode image
			img, _, err := image.Decode(src)
			if err != nil {
				h.logger.Error("failed to decode image", zap.Error(err))
				return
			}

			// Resize image to 1024x768 (hospital images can be larger)
			resized := resize.Resize(1024, 768, img, resize.Lanczos3)

			// Convert to JPEG and compress
			buf := new(bytes.Buffer)
			if err := jpeg.Encode(buf, resized, &jpeg.Options{Quality: jpegQuality}); err != nil {
				h.logger.Error("failed to encode image", zap.Error(err))
				return
			}

			// Generate unique filename
			filename := fmt.Sprintf("%s.jpg", uuid.New().String())

			// Upload to MinIO
			info, err := h.minioClient.PutObject(
				ctx,
				hospitalBucketName,
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
					zap.String("bucketName", hospitalBucketName),
					zap.String("filename", filename))
				return
			}

			// Verify upload was successful
			if info.Size == 0 {
				h.logger.Error("upload completed but file size is 0",
					zap.String("filename", filename))
				return
			}

			_, err = h.minioClient.StatObject(ctx, hospitalBucketName, filename, minio.StatObjectOptions{})
			if err != nil {
				h.logger.Error("failed to verify uploaded object",
					zap.Error(err),
					zap.String("filename", filename))
				return
			}

			h.logger.Info("successfully uploaded hospital image to minio",
				zap.String("bucket", hospitalBucketName),
				zap.String("filename", filename),
				zap.Any("info", info),
			)

			// Store only the filename
			filenames = append(filenames, filename)

			// Prepare document for MongoDB
			mongoImageDocs = append(mongoImageDocs, bson.M{
				"filename":        filename,
				"hospital_id":     hospitalID,
				"organization_id": organizationID,
				"bucket":          hospitalBucketName,
				"content_type":    "image/jpeg",
				"size":            info.Size,
				"created_at":      time.Now(),
			})
		}(src)
	}

	// Insert image references into MongoDB
	if len(mongoImageDocs) > 0 {
		// Get MongoDB collection
		collection := h.mongoClient.Database("hospital_db").Collection("hospital_images")

		// Insert documents
		_, err := collection.InsertMany(ctx, mongoImageDocs)
		if err != nil {
			h.logger.Error("failed to store image references in MongoDB",
				zap.Error(err),
				zap.String("hospital_id", hospitalID))
			return nil, fiber.NewError(fiber.StatusInternalServerError, "Failed to store image references")
		}

		h.logger.Info("successfully stored image references in MongoDB",
			zap.Int("count", len(mongoImageDocs)),
			zap.String("hospital_id", hospitalID))
	}

	return filenames, nil
}

// DeleteHospitalImage deletes a specific hospital image
func (h *HospitalHandler) DeleteHospitalImage(c *fiber.Ctx) error {
	hospitalID := c.Params("hospitalId")
	filename := c.Params("filename")

	if hospitalID == "" || filename == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Hospital ID and filename are required",
		})
	}

	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	// Find the image document to get the bucket name
	collection := h.mongoClient.Database("hospital_db").Collection("hospital_images")
	var imageDoc struct {
		Bucket string `bson:"bucket"`
	}

	err := collection.FindOne(ctx, bson.M{
		"hospital_id": hospitalID,
		"filename":    filename,
	}).Decode(&imageDoc)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Image not found",
			})
		}
		h.logger.Error("failed to find image document", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve image information",
		})
	}

	// Delete the image from MinIO
	err = h.minioClient.RemoveObject(ctx, imageDoc.Bucket, filename, minio.RemoveObjectOptions{})
	if err != nil {
		h.logger.Error("failed to delete image from MinIO",
			zap.Error(err),
			zap.String("bucket", imageDoc.Bucket),
			zap.String("filename", filename))
		// Continue to delete from MongoDB even if MinIO delete fails
	}

	// Delete the image reference from MongoDB
	result, err := collection.DeleteOne(ctx, bson.M{
		"hospital_id": hospitalID,
		"filename":    filename,
	})

	if err != nil {
		h.logger.Error("failed to delete image reference from MongoDB", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete image reference",
		})
	}

	if result.DeletedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Image not found",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "Image successfully deleted",
		"filename": filename,
	})
}

// GetHospitalImages retrieves all images for a specific hospital from MongoDB
func (h *HospitalHandler) GetHospitalImages(c *fiber.Ctx) error {
	hospitalID := c.Params("hospitalId")
	if hospitalID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Hospital ID is required"})
	}

	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	// Get MongoDB collection
	collection := h.mongoClient.Database("hospital_db").Collection("hospital_images")

	// Find all images for this hospital
	cursor, err := collection.Find(ctx, bson.M{"hospital_id": hospitalID})
	if err != nil {
		h.logger.Error("failed to query hospital images from MongoDB",
			zap.Error(err),
			zap.String("hospital_id", hospitalID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve hospital images"})
	}
	defer cursor.Close(ctx)

	// Decode the results
	var images []struct {
		Filename  string    `bson:"filename"`
		Bucket    string    `bson:"bucket"`
		CreatedAt time.Time `bson:"created_at"`
	}

	if err := cursor.All(ctx, &images); err != nil {
		h.logger.Error("failed to decode hospital images from MongoDB", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process hospital images"})
	}

	// Convert to response format
	var response []map[string]interface{}
	for _, img := range images {
		imageURL := fmt.Sprintf("%s/%s/%s", h.config.MinioEndpoint, img.Bucket, img.Filename)
		response = append(response, map[string]interface{}{
			"filename":   img.Filename,
			"url":        imageURL,
			"created_at": img.CreatedAt,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// CreateHospital function to handle hospital creation with MongoDB for images
func (h *HospitalHandler) CreateHospital(c *fiber.Ctx) error {
	// Check for Admin role in X-Role header
	/*roleHeader := c.Get("X-Role")
	if roleHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Role information missing"})
	}
	h.logger.Info("Role header", zap.String("role", roleHeader))

	// Check if "admin" is one of the roles (allows for multiple roles like "Admin,Doctor")
	// Fixed to make role check case-insensitive
	roles := strings.Split(roleHeader, ",")
	hasAdminRole := false
	for _, role := range roles {
		if strings.EqualFold(strings.TrimSpace(role), "admin") {
			hasAdminRole = true
			break
		}
	}
	if !hasAdminRole {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "You don't have permission to create a hospital"})
	}
	*/
	// Get the auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Parse the rest of the form data
	var hospitalData Hospital
	if err := c.BodyParser(&hospitalData); err != nil {
		h.logger.Error("failed to parse hospital data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	// Validate start and end times are provided
	if hospitalData.StartTime == "" || hospitalData.EndTime == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "start time and end time are required"})
	}

	// Validate time format
	_, err = time.Parse("15:04:05", hospitalData.StartTime)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid start time format, use HH:MM:SS"})
	}

	_, err = time.Parse("15:04:05", hospitalData.EndTime)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid end time format, use HH:MM:SS"})
	}

	if err := h.validateHospitalData(&hospitalData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Start a transaction for PostgreSQL operations
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(c.Context()); rbErr != nil {
				h.logger.Error("failed to rollback transaction", zap.Error(rbErr))
			}
		}
	}()

	// Let PostgreSQL generate the UUID for us
	var hospitalID uuid.UUID
	err = tx.QueryRow(c.Context(),
		`INSERT INTO hospitals (
			admin_id, org_id, name, email, number, address, license_number,
			start_time, end_time, location, speciality
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING hospital_id`,
		userID, "", hospitalData.Name, hospitalData.Email, hospitalData.Number, hospitalData.Address,
		hospitalData.LicenseNumber, hospitalData.StartTime, hospitalData.EndTime, hospitalData.Location,
		hospitalData.Speciality,
	).Scan(&hospitalID)

	if err != nil {
		h.logger.Error("failed to insert hospital data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create hospital"})
	}

	// Create a WorkOS organization for the hospital
	org, err := organizations.CreateOrganization(
		c.Context(),
		organizations.CreateOrganizationOpts{
			Name: hospitalData.Name,
			// Add a domain based on the hospital name
			DomainData: []organizations.OrganizationDomainData{
				{
					Domain: strings.ToLower(strings.ReplaceAll(hospitalData.Name, " ", "-")) + ".example.com",
					State:  organizations.Pending,
				},
			},
			IdempotencyKey:                   uuid.New().String(), // Add idempotency key
			AllowProfilesOutsideOrganization: false,
			ExternalID:                       hospitalID.String(),
			Metadata: map[string]string{
				"admin_id":    userID.String(),
				"hospital_id": hospitalID.String(),
				"location":    hospitalData.Location,
				"name":        hospitalData.Name,
				"email":       hospitalData.Email,
				"speciality":  hospitalData.Speciality,
			},
		},
	)
	if err != nil {
		h.logger.Error("failed to create WorkOS organization", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create organization for hospital",
		})
	}

	// Create the user in the WorkOS organization
	userResponse, err := usermanagement.CreateOrganizationMembership(
		c.Context(),
		usermanagement.CreateOrganizationMembershipOpts{
			OrganizationID: org.ID,
			UserID:         authID, // Use the authID from context which is the WorkOS user ID
			RoleSlug:       "admin",
		},
	)
	if err != nil {
		h.logger.Error("failed to create WorkOS organization membership", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to add user to organization",
		})
	}

	// Log the success
	h.logger.Info("created WorkOS organization membership",
		zap.String("user_id", authID),
		zap.String("org_id", org.ID),
		zap.String("membership_id", userResponse.ID))

	// Update the hospital with the WorkOS org ID
	_, err = tx.Exec(c.Context(),
		`UPDATE hospitals SET org_id = $1 WHERE hospital_id = $2`,
		org.ID, hospitalID)
	if err != nil {
		h.logger.Error("failed to update hospital with org ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update hospital"})
	}

	// Commit the PostgreSQL transaction
	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Test MinIO connection before upload
	if err := h.testMinioConnection(c.Context()); err != nil {
		h.logger.Error("MinIO connection failed", zap.Error(err))
		// Continue with the hospital creation but log the error
		// Return the created hospital without images
		hospitalData.ID = hospitalID
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"hospital": hospitalData,
			"warning":  "Hospital created but image upload failed due to storage service issues",
		})
	}

	// Now upload hospital images and store references in MongoDB
	filenames, err := h.UploadHospitalImages(c, hospitalID.String(), org.ID)
	if err != nil {
		h.logger.Error("failed to upload hospital images", zap.Error(err))
		// If image upload fails, we should log it but not fail the entire operation
		// since the hospital record is already created
		hospitalData.ID = hospitalID
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"hospital": hospitalData,
			"warning":  "Hospital created but image upload failed"})
	}

	// For the response, construct full URLs from the filenames
	imageURLs := make([]string, len(filenames))
	for i, filename := range filenames {
		imageURLs[i] = fmt.Sprintf("%s/%s/%s", h.config.MinioEndpoint, "hospital-pics", filename)
	}

	// Add the image URLs to the response
	hospitalData.HospitalPics = imageURLs
	hospitalData.ID = hospitalID

	// Return the created hospital with its ID
	return c.Status(fiber.StatusCreated).JSON(hospitalData)
}

// testMinioConnection checks if the MinIO connection is working
func (h *HospitalHandler) testMinioConnection(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// A simple operation to check if MinIO is available
	_, err := h.minioClient.ListBuckets(ctx)
	if err != nil {
		h.logger.Error("MinIO connection test failed", zap.Error(err))
		return err
	}

	return nil
}

// GetHospital retrieves a specific hospital by ID
func (h *HospitalHandler) GetHospital(c *fiber.Ctx) error {
	hospitalID := c.Params("id")
	if hospitalID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Hospital ID is required"})
	}

	parsedHospitalID, err := uuid.Parse(hospitalID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid hospital ID format"})
	}

	var hospital Hospital
	var createdAt time.Time

	// Get hospital data from PostgreSQL (without hospital_pics field)
	err = h.pgPool.QueryRow(c.Context(),
		`SELECT 
			id, admin_id, org_id, name, email, number, address, license_number, 
			start_time, end_time, location, speciality, created_at
		FROM hospitals WHERE id = $1`,
		parsedHospitalID).Scan(
		&hospital.ID,
		&hospital.AdminID,
		&hospital.OrgID,
		&hospital.Name,
		&hospital.Email,
		&hospital.Number,
		&hospital.Address,
		&hospital.LicenseNumber,
		&hospital.StartTime,
		&hospital.EndTime,
		&hospital.Location,
		&hospital.Speciality,
		&createdAt,
	)
	if err != nil {
		h.logger.Error("failed to fetch hospital", zap.Error(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Hospital not found"})
	}

	hospital.CreatedAt = createdAt.Format(time.RFC3339)

	// Get hospital fees
	rows, err := h.pgPool.Query(c.Context(),
		`SELECT id, fee_type, amount, created_at
		FROM hospital_fees
		WHERE hospital_id = $1`,
		parsedHospitalID)
	if err != nil {
		h.logger.Error("failed to fetch hospital fees", zap.Error(err))
	} else {
		defer rows.Close()

		for rows.Next() {
			var fee HospitalFee
			var feeCreatedAt time.Time

			err := rows.Scan(&fee.ID, &fee.FeeType, &fee.Amount, &feeCreatedAt)
			if err != nil {
				h.logger.Error("failed to scan fee row", zap.Error(err))
				continue
			}

			fee.CreatedAt = feeCreatedAt.Format(time.RFC3339)
			hospital.Fees = append(hospital.Fees, fee)
		}
	}

	// Get hospital images from MongoDB
	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	collection := h.mongoClient.Database("hospital_db").Collection("hospital_images")
	cursor, err := collection.Find(ctx, bson.M{"hospital_id": hospitalID})

	if err == nil {
		defer cursor.Close(ctx)

		var images []struct {
			Filename string `bson:"filename"`
			Bucket   string `bson:"bucket"`
		}

		if err := cursor.All(ctx, &images); err == nil {
			imageURLs := make([]string, 0, len(images))
			for _, img := range images {
				imageURL := fmt.Sprintf("%s/%s/%s", h.config.MinioEndpoint, img.Bucket, img.Filename)
				imageURLs = append(imageURLs, imageURL)
			}
			hospital.HospitalPics = imageURLs
		} else {
			h.logger.Error("failed to decode hospital images", zap.Error(err))
		}
	} else {
		h.logger.Error("failed to query hospital images", zap.Error(err))
	}

	return c.JSON(hospital)
}

// UpdateHospital updates an existing hospital
func (h *HospitalHandler) UpdateHospital(c *fiber.Ctx) error {
	hospitalID := c.Params("id")
	if hospitalID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Hospital ID is required"})
	}

	parsedHospitalID, err := uuid.Parse(hospitalID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid hospital ID format"})
	}

	// Check permissions
	roleHeader := c.Get("X-Role")
	if roleHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Role information missing"})
	}

	// Check if "Admin" or "Manager" is one of the roles
	roles := strings.Split(roleHeader, ",")
	hasRequiredRole := false
	for _, role := range roles {
		trimmedRole := strings.TrimSpace(role)
		if trimmedRole == "admin" || trimmedRole == "manager" {
			hasRequiredRole = true
			break
		}
	}

	if !hasRequiredRole {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "You don't have permission to update a hospital"})
	}

	var updateData Hospital
	if err := c.BodyParser(&updateData); err != nil {
		h.logger.Error("failed to parse update data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	if err := h.validateHospitalData(&updateData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Get the current WorkOS organization ID
	var orgID string
	err = h.pgPool.QueryRow(c.Context(),
		"SELECT org_id FROM hospitals WHERE id = $1",
		parsedHospitalID).Scan(&orgID)
	if err != nil {
		h.logger.Error("failed to get hospital org_id", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Update the WorkOS organization
	_, err = organizations.UpdateOrganization(
		c.Context(),
		organizations.UpdateOrganizationOpts{
			Organization: orgID,
			Name:         updateData.Name,
		},
	)
	if err != nil {
		h.logger.Error("failed to update WorkOS organization", zap.Error(err))
		// Continue anyway, as the database update is more important
	}

	// Start a transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	defer tx.Rollback(c.Context())

	// Update the hospital in the database (without hospital_pics field)
	_, err = tx.Exec(c.Context(),
		`UPDATE hospitals SET 
			name = $1, email = $2, number = $3, address = $4, license_number = $5,
			start_time = $6, end_time = $7, location = $8, speciality = $9
		WHERE id = $10`,
		updateData.Name, updateData.Email, updateData.Number, updateData.Address, updateData.LicenseNumber,
		updateData.StartTime, updateData.EndTime, updateData.Location, updateData.Speciality,
		parsedHospitalID,
	)
	if err != nil {
		h.logger.Error("failed to update hospital data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update hospital"})
	}

	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// If new images are uploaded, process them
	if form, err := c.MultipartForm(); err == nil && form.File["hospitalPics"] != nil && len(form.File["hospitalPics"]) > 0 {
		filenames, err := h.UploadHospitalImages(c, hospitalID, orgID)
		if err != nil {
			h.logger.Error("failed to upload new hospital images", zap.Error(err))
			// Continue anyway to return the updated hospital data
		} else {
			h.logger.Info("uploaded new hospital images",
				zap.Int("count", len(filenames)),
				zap.String("hospital_id", hospitalID))
		}
	}

	// Return updated hospital data
	return h.GetHospital(c)
}

// DeleteHospital removes a hospital
func (h *HospitalHandler) DeleteHospital(c *fiber.Ctx) error {
	hospitalID := c.Params("id")
	if hospitalID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Hospital ID is required"})
	}

	parsedHospitalID, err := uuid.Parse(hospitalID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid hospital ID format"})
	}

	// Only allow the admin to update their own hospital or if user is system admin
	roleHeader := c.Get("X-Role")
	if roleHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Role information missing"})
	}

	// Check if "Admin", "Doctor", or "Manager" is one of the roles
	roles := strings.Split(roleHeader, ",")
	hasRequiredRole := false
	for _, role := range roles {
		trimmedRole := strings.TrimSpace(role)
		if trimmedRole == "Admin" || trimmedRole == "Manager" {
			hasRequiredRole = true
			break
		}
	}

	if !hasRequiredRole {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "You don't have permission to create a hospital"})
	}

	// Get the WorkOS organization ID
	var orgID string
	err = h.pgPool.QueryRow(c.Context(), "SELECT org_id FROM hospitals WHERE admin_id = $1", parsedHospitalID).Scan(&orgID)
	if err != nil {
		h.logger.Error("failed to get hospital org_id", zap.Error(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Hospital not found"})
	}

	// Start a transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	defer tx.Rollback(c.Context())

	// Delete hospital fees
	_, err = tx.Exec(c.Context(), "DELETE FROM hospital_fees WHERE hospital_id = $1", parsedHospitalID)
	if err != nil {
		h.logger.Error("failed to delete hospital fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Delete hospital
	_, err = tx.Exec(c.Context(), "DELETE FROM hospitals WHERE admin_id = $1", parsedHospitalID)
	if err != nil {
		h.logger.Error("failed to delete hospital", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Delete the WorkOS organization
	err = organizations.DeleteOrganization(
		c.Context(),
		organizations.DeleteOrganizationOpts{
			Organization: orgID,
		},
	)
	if err != nil {
		h.logger.Error("failed to delete WorkOS organization", zap.Error(err))
		// Continue anyway as the database operation succeeded
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Hospital deleted successfully"})
}

// ListHospitals returns a list of hospitals
func (h *HospitalHandler) ListHospitals(c *fiber.Ctx) error {
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	fmt.Println(userID)
	// Get all hospitals
	rows, err := h.pgPool.Query(c.Context(),
		`SELECT 
			admin_id, org_id, name, email, number, address, license_number, 
			start_time, end_time, location, hospital_pics, speciality, created_at
		FROM hospitals ORDER BY name`)
	if err != nil {
		h.logger.Error("failed to query hospitals", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	defer rows.Close()

	hospitals := []Hospital{}
	for rows.Next() {
		var hospital Hospital
		var createdAt time.Time

		err := rows.Scan(
			&hospital.AdminID,
			&hospital.OrgID,
			&hospital.Name,
			&hospital.Email,
			&hospital.Number,
			&hospital.Address,
			&hospital.LicenseNumber,
			&hospital.StartTime,
			&hospital.EndTime,
			&hospital.Location,
			&hospital.HospitalPics,
			&hospital.Speciality,
			&createdAt,
		)
		if err != nil {
			h.logger.Error("failed to scan hospital row", zap.Error(err))
			continue
		}

		hospital.CreatedAt = createdAt.Format(time.RFC3339)
		hospitals = append(hospitals, hospital)
	}

	// Get fees for all hospitals in one query for efficiency
	feesMap := make(map[uuid.UUID][]HospitalFee)
	feeRows, err := h.pgPool.Query(c.Context(),
		`SELECT id, hospital_id, fee_type, amount, created_at
		FROM hospital_fees`)
	if err == nil {
		defer feeRows.Close()

		for feeRows.Next() {
			var fee HospitalFee
			var hospitalID uuid.UUID
			var createdAt time.Time

			err := feeRows.Scan(&fee.ID, &hospitalID, &fee.FeeType, &fee.Amount, &createdAt)
			if err != nil {
				h.logger.Error("failed to scan fee row", zap.Error(err))
				continue
			}

			fee.CreatedAt = createdAt.Format(time.RFC3339)
			feesMap[hospitalID] = append(feesMap[hospitalID], fee)
		}

		// Add fees to their respective hospitals
		for i := range hospitals {
			hospitals[i].Fees = feesMap[hospitals[i].AdminID]
		}
	}

	return c.JSON(hospitals)
}

// validateHospitalData validates hospital input data
func (h *HospitalHandler) validateHospitalData(hospital *Hospital) error {
	if hospital.Name == "" {
		return errors.New("Hospital name is required")
	}

	if hospital.Email == "" {
		return errors.New("Hospital email is required")
	}

	// Basic email format validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(hospital.Email) {
		return errors.New("invalid email format")
	}

	if hospital.Address == "" {
		return errors.New("Hospital address is required")
	}

	if hospital.Location == "" {
		return errors.New("Hospital location is required")
	}

	if hospital.Number == 0 {
		return errors.New("Hospital number is required")
	}

	return nil
}
