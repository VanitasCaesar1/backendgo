// doctor handler
package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
	"go.uber.org/zap"
)

type DoctorHandler struct {
	config      *config.Config
	redisClient *redis.Client
	logger      *zap.Logger
	pgPool      *pgxpool.Pool
}

type Specialization struct {
	Primary   string   `json:"primary"`
	Secondary []string `json:"secondary,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// DoctorSlot represents a single appointment slot
type DoctorSlot struct {
	SlotID         uuid.UUID  `json:"slotID"`
	DoctorID       uuid.UUID  `json:"doctorID"`
	OrganizationID string     `json:"organizationID"`
	SlotDate       time.Time  `json:"slotDate"`
	SlotStartTime  string     `json:"slotStartTime"`
	SlotEndTime    string     `json:"slotEndTime"`
	Weekday        string     `json:"weekday"`
	IsBooked       bool       `json:"isBooked"`
	IsActive       bool       `json:"isActive"`
	AppointmentID  *uuid.UUID `json:"appointmentID,omitempty"`
}

// SlotResponse is used for API responses
type SlotResponse struct {
	SlotID         string `json:"slotID"`
	DoctorID       string `json:"doctorID"`
	OrganizationID string `json:"organizationID"`
	SlotDate       string `json:"slotDate"`
	SlotStartTime  string `json:"slotStartTime"`
	SlotEndTime    string `json:"slotEndTime"`
	Weekday        string `json:"weekday"`
	IsBooked       bool   `json:"isBooked"`
	IsActive       bool   `json:"isActive"`
}

type DoctorProfile struct {
	UserID            uuid.UUID      `json:"user_id"`
	AuthID            string         `json:"auth_id,omitempty"`
	Username          string         `json:"username"`
	ProfilePictureURL string         `json:"profile_picture_url,omitempty"`
	Name              string         `json:"name"`
	Mobile            string         `json:"mobile"`
	Email             string         `json:"email"`
	BloodGroup        string         `json:"blood_group,omitempty"`
	Location          string         `json:"location"`
	Address           string         `json:"address,omitempty"`
	IMRNumber         string         `json:"imr_number,omitempty"`
	Age               int            `json:"age,omitempty"`
	Specialization    Specialization `json:"specialization,omitempty"`
	IsActive          bool           `json:"is_active,omitempty"`
	Qualification     string         `json:"qualification,omitempty"`
	SlotDuration      int            `json:"slot_duration,omitempty"`
	HospitalID        uuid.UUID      `json:"hospital_id,omitempty"`
	CreatedAt         string         `json:"created_at,omitempty"`
	UpdatedAt         string         `json:"updated_at,omitempty"`
	YearsOfExperience int            `json:"years_of_experience,omitempty"`
	Bio               string         `json:"bio,omitempty"`
	LanguagesSpoken   []string       `json:"languages_spoken,omitempty"`
}

// DoctorSchedule struct with ID field
type DoctorSchedule struct {
	ID             string `json:"id,omitempty"`
	DoctorID       string `json:"doctorID" form:"doctorID"`
	OrganizationID string `json:"organizationID" form:"organizationID"`
	DoctorName     string `json:"doctorName,omitempty"`
	Weekday        string `json:"weekday" form:"weekday"`
	StartTime      string `json:"startTime" form:"startTime"`
	EndTime        string `json:"endTime" form:"endTime"`
	IsActive       bool   `json:"isActive" form:"isActive"`
}

type DoctorFees struct {
	DoctorID       string `json:"doctorID"` // Changed to string to match incoming JSON
	OrganizationID string `json:"organization_id"`
	DoctorName     string `json:"doctor_name"`
	RecurringFees  int    `json:"recurring_fees"`
	DefaultFees    int    `json:"default_fees"`
	EmergencyFees  int    `json:"emergency_fees"`
	CreatedAt      string `json:"created_at,omitempty"`
}

func NewDoctorHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, pgPool *pgxpool.Pool) (*DoctorHandler, error) {
	usermanagement.SetAPIKey(cfg.WorkOSApiKey)
	return &DoctorHandler{
		config:      cfg,
		redisClient: rds,
		logger:      logger,
		pgPool:      pgPool,
	}, nil
}

// Helper functions
func (h *DoctorHandler) getUserID(ctx context.Context, authID string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := h.pgPool.QueryRow(ctx, "SELECT user_id FROM users WHERE auth_id = $1", authID).Scan(&userID)
	return userID, err
}

func (h *DoctorHandler) getAuthID(c *fiber.Ctx) (string, error) {
	authID, ok := c.Locals("authID").(string)
	if !ok {
		return "", errors.New("user ID not found")
	}
	return authID, nil
}

// GetDoctorProfile retrieves a doctor's complete profile by ID
func (h *DoctorHandler) GetDoctorProfile(c *fiber.Ctx) error {
	// Get the doctor ID from URL parameter
	doctorID := c.Params("id")
	if doctorID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Doctor ID is required",
		})
	}

	// Validate UUID format
	doctorUUID, err := uuid.Parse(doctorID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid doctor ID format",
		})
	}

	h.logger.Info("processing doctor profile request",
		zap.String("doctorID", doctorID))

	// Get complete user info and doctor-specific data in one query
	var profile DoctorProfile
	var specializationJSON []byte
	var languagesJSON []byte

	err = h.pgPool.QueryRow(c.Context(),
		`SELECT
			u.user_id,
			u.auth_id,
			COALESCE(u.username, '') as username,
			COALESCE(u.profile_pic, '') as profile_pic,
			COALESCE(u.name, '') as name,
			COALESCE(CAST(u.mobile AS TEXT), '') as mobile,
			COALESCE(u.email, '') as email,
			COALESCE(u.blood_group, '') as blood_group,
			COALESCE(u.location, '') as location,
			COALESCE(u.address, '') as address,
			u.hospital_id,
			COALESCE(d.imr_number, '') as imr_number,
			d.age,
			d.specialization,
			d.is_active,
			COALESCE(d.qualification, '') as qualification,
			COALESCE(d.slot_duration, 30) as slot_duration,
			COALESCE(d.years_of_experience, 0) as years_of_experience,
			COALESCE(d.bio, '') as bio,
			COALESCE(d.languages_spoken, '[]'::jsonb) as languages_spoken
		FROM users u
		JOIN doctors d ON u.user_id = d.doctor_id
		WHERE d.doctor_id = $1`,
		doctorUUID).Scan(
		&profile.UserID,
		&profile.AuthID,
		&profile.Username,
		&profile.ProfilePictureURL,
		&profile.Name,
		&profile.Mobile,
		&profile.Email,
		&profile.BloodGroup,
		&profile.Location,
		&profile.Address,
		&profile.HospitalID,
		&profile.IMRNumber,
		&profile.Age,
		&specializationJSON,
		&profile.IsActive,
		&profile.Qualification,
		&profile.SlotDuration,
		&profile.YearsOfExperience,
		&profile.Bio,
		&languagesJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			h.logger.Info("doctor profile not found", zap.String("doctorID", doctorID))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Doctor profile not found"})
		}
		h.logger.Error("failed to fetch doctor profile", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch doctor profile"})
	}

	// Debug logging for specialization
	h.logger.Info("raw specialization from database",
		zap.String("doctorID", doctorID),
		zap.ByteString("specializationJSON", specializationJSON),
		zap.Int("length", len(specializationJSON)))

	// FIXED: Simplified specialization parsing
	if len(specializationJSON) > 0 {
		specializationStr := string(specializationJSON)
		h.logger.Info("specialization string from database",
			zap.String("doctorID", doctorID),
			zap.String("specializationStr", specializationStr))

		// Initialize with empty values
		profile.Specialization = Specialization{Primary: "", Secondary: []string{}}

		// Try to parse as JSON object first
		var tempSpec map[string]interface{}
		if err := json.Unmarshal(specializationJSON, &tempSpec); err == nil {
			// Successfully parsed as object
			h.logger.Info("parsed specialization as object",
				zap.String("doctorID", doctorID),
				zap.Any("tempSpec", tempSpec))

			// Extract primary specialization
			if primary, exists := tempSpec["primary"]; exists {
				if primaryStr, ok := primary.(string); ok && strings.TrimSpace(primaryStr) != "" {
					profile.Specialization.Primary = strings.TrimSpace(primaryStr)
				}
			}

			// Extract secondary specializations
			if secondary, exists := tempSpec["secondary"]; exists {
				if secondarySlice, ok := secondary.([]interface{}); ok {
					for _, item := range secondarySlice {
						if itemStr, ok := item.(string); ok && strings.TrimSpace(itemStr) != "" {
							profile.Specialization.Secondary = append(profile.Specialization.Secondary, strings.TrimSpace(itemStr))
						}
					}
				}
			}

			// FIXED: If primary is missing, null, or empty, look for any other string value in the object
			if profile.Specialization.Primary == "" {
				for key, value := range tempSpec {
					if key == "secondary" {
						continue // Skip secondary array
					}
					if valueStr, ok := value.(string); ok && strings.TrimSpace(valueStr) != "" {
						profile.Specialization.Primary = strings.TrimSpace(valueStr)
						h.logger.Info("used fallback primary specialization",
							zap.String("doctorID", doctorID),
							zap.String("key", key),
							zap.String("value", profile.Specialization.Primary))
						break
					}
				}
			}
		} else {
			// Try parsing as string
			var specializationString string
			if err := json.Unmarshal(specializationJSON, &specializationString); err == nil {
				if strings.TrimSpace(specializationString) != "" {
					profile.Specialization.Primary = strings.TrimSpace(specializationString)
					h.logger.Info("parsed specialization as string",
						zap.String("doctorID", doctorID),
						zap.String("value", profile.Specialization.Primary))
				}
			} else {
				// If both fail, treat the raw string as primary
				if strings.TrimSpace(specializationStr) != "" &&
					specializationStr != "null" &&
					specializationStr != "{}" {
					profile.Specialization.Primary = strings.TrimSpace(specializationStr)
					h.logger.Info("used raw string as primary specialization",
						zap.String("doctorID", doctorID),
						zap.String("value", profile.Specialization.Primary))
				}
			}
		}
	} else {
		h.logger.Warn("specialization JSON is empty - this shouldn't happen with NOT NULL constraint",
			zap.String("doctorID", doctorID))
		profile.Specialization = Specialization{Primary: "", Secondary: []string{}}
	}

	// Parse languages (keep existing logic)
	if len(languagesJSON) > 0 {
		if string(languagesJSON) == "null" {
			profile.LanguagesSpoken = []string{}
		} else {
			if err := json.Unmarshal(languagesJSON, &profile.LanguagesSpoken); err != nil {
				h.logger.Error("failed to parse languages JSON",
					zap.Error(err),
					zap.String("doctorID", doctorID),
					zap.ByteString("rawJSON", languagesJSON))
				profile.LanguagesSpoken = []string{}
			}
		}
	} else {
		profile.LanguagesSpoken = []string{}
	}

	// Final debug log
	h.logger.Info("doctor profile retrieved successfully",
		zap.String("doctorID", doctorID),
		zap.String("doctorName", profile.Name),
		zap.String("finalSpecializationPrimary", profile.Specialization.Primary),
		zap.Strings("finalSpecializationSecondary", profile.Specialization.Secondary),
		zap.Strings("finalLanguages", profile.LanguagesSpoken))

	return c.JSON(profile)
}

func (h *DoctorHandler) GetDoctorSchedule(c *fiber.Ctx) error {
	// Get doctor ID from URL parameter
	doctorIDParam := c.Params("id")
	if doctorIDParam == "" {
		h.logger.Error("doctor ID not found in URL parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor ID is required"})
	}

	// Parse the doctor ID to UUID
	doctorID, err := uuid.Parse(doctorIDParam)
	if err != nil {
		h.logger.Error("invalid doctor ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid doctor ID format"})
	}

	// Get organization ID from context
	orgID := c.Get("X-Organization-ID")
	if orgID == "" {
		h.logger.Error("organization ID not found in request headers")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required"})
	}

	h.logger.Info("Processing schedule request",
		zap.String("doctorID", doctorID.String()),
		zap.String("orgID", orgID))

	// Check if the user is authenticated
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println(authID)

	// Initialize schedules slice
	schedules := []map[string]interface{}{}

	// Query to fetch doctor schedules
	rows, err := h.pgPool.Query(c.Context(),
		`SELECT doctor_id, organization_id, weekday, starttime, endtime, isactive
         FROM doctorshifts
         WHERE doctor_id = $1 AND organization_id = $2`,
		doctorID, orgID)

	if err != nil {
		h.logger.Error("failed to fetch doctor schedule", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch doctor schedule"})
	}
	defer rows.Close()

	// Process each row
	for rows.Next() {
		var (
			doctorID       uuid.UUID
			organizationID string
			weekday        string
			startTime      time.Time
			endTime        time.Time
			isActive       bool
		)

		// Scan row data
		if err := rows.Scan(
			&doctorID,
			&organizationID,
			&weekday,
			&startTime,
			&endTime,
			&isActive); err != nil {
			h.logger.Error("failed to scan doctor schedule row", zap.Error(err))
			continue
		}

		// Get doctor name from a separate query
		var doctorName string
		err := h.pgPool.QueryRow(c.Context(),
			"SELECT name FROM doctors WHERE doctor_id = $1",
			doctorID).Scan(&doctorName)

		if err != nil {
			if err == pgx.ErrNoRows {
				h.logger.Warn("doctor not found in doctors table", zap.String("doctorID", doctorID.String()))
				doctorName = ""
			} else {
				h.logger.Error("failed to get doctor name", zap.Error(err))
				doctorName = ""
			}
		}

		// Create a composite ID string for frontend
		compositeID := fmt.Sprintf("%s_%s_%s", doctorID.String(), weekday, organizationID)

		// Format the schedule data
		schedule := map[string]interface{}{
			"id":             compositeID,
			"doctorID":       doctorID.String(),
			"organizationID": organizationID,
			"doctorName":     doctorName,
			"weekday":        weekday,
			"startTime":      startTime.Format("15:04"),
			"endTime":        endTime.Format("15:04"),
			"isActive":       isActive,
		}

		h.logger.Debug("Schedule found",
			zap.String("id", compositeID),
			zap.String("weekday", weekday),
			zap.String("startTime", startTime.Format("15:04")))

		// Add schedule to the slice
		schedules = append(schedules, schedule)
	}

	// Check for errors after iterating through rows
	if err := rows.Err(); err != nil {
		h.logger.Error("error during schedule rows iteration", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process doctor schedule"})
	}

	// Check if schedules is empty and log that fact
	if len(schedules) == 0 {
		h.logger.Info("no schedules found for doctor",
			zap.String("doctorID", doctorID.String()),
			zap.String("orgID", orgID))
	} else {
		h.logger.Info("found schedules for doctor",
			zap.String("doctorID", doctorID.String()),
			zap.Int("count", len(schedules)))
	}

	// Wrap schedules in a response object to match what frontend expects
	response := map[string]interface{}{
		"data": schedules,
	}

	// Log the final JSON being sent
	jsonBytes, _ := json.Marshal(response)
	h.logger.Info("returning response", zap.String("json", string(jsonBytes)))

	// Return the response
	return c.JSON(response)
}

// GetDoctorFees retrieves the doctor's fees structure
func (h *DoctorHandler) GetDoctorFees(c *fiber.Ctx) error {
	// Get doctor ID from path parameter instead of using the authenticated user's ID
	doctorID := c.Params("id")
	if doctorID == "" {
		h.logger.Error("doctor ID not found in path parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor ID is required"})
	}

	// Get organization ID from context
	orgID := c.Get("X-Organization-ID")
	if orgID == "" {
		h.logger.Error("organization ID not found in request headers")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required"})
	}

	h.logger.Info("Fetching fees", zap.String("doctor_id", doctorID), zap.String("org_id", orgID))

	// Use JOIN to get doctor name from the doctors table
	rows, err := h.pgPool.Query(c.Context(),
		`SELECT df.doctor_id, df.organization_id, d.name AS doctor_name,
         df.recurring_fees, df.default_fees, df.emergency_fees, df.created_at
         FROM doctor_fees df
         JOIN doctors d ON df.doctor_id = d.doctor_id
         WHERE df.doctor_id = $1 AND df.organization_id = $2`, doctorID, orgID)

	if err != nil {
		h.logger.Error("failed to fetch doctor fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch doctor fees"})
	}
	defer rows.Close()

	var feesStructures []DoctorFees
	for rows.Next() {
		var fees DoctorFees
		var createdAt time.Time
		if err := rows.Scan(&fees.DoctorID, &fees.OrganizationID, &fees.DoctorName, &fees.RecurringFees,
			&fees.DefaultFees, &fees.EmergencyFees, &createdAt); err != nil {
			h.logger.Error("failed to scan doctor fees", zap.Error(err))
			continue
		}
		fees.CreatedAt = createdAt.Format(time.RFC3339)
		feesStructures = append(feesStructures, fees)
	}

	if err := rows.Err(); err != nil {
		h.logger.Error("error during fees rows scan", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process doctor fees"})
	}

	// Add debug logging to see what's being returned
	h.logger.Info("Returning fees", zap.Int("count", len(feesStructures)))

	// If no fees found, return an empty array instead of null
	if len(feesStructures) == 0 {
		return c.JSON([]DoctorFees{})
	}

	return c.JSON(feesStructures)
}

type DoctorProfileUpdate struct {
	Username          *string         `json:"username,omitempty"`
	Name              *string         `json:"name,omitempty"`
	Mobile            *string         `json:"mobile,omitempty"`
	BloodGroup        *string         `json:"blood_group,omitempty"`
	Location          *string         `json:"location,omitempty"`
	Address           *string         `json:"address,omitempty"`
	IMRNumber         *string         `json:"imr_number,omitempty"`
	Age               *int            `json:"age,omitempty"`
	Specialization    *Specialization `json:"specialization,omitempty"`
	IsActive          *bool           `json:"is_active,omitempty"`
	Qualification     *string         `json:"qualification,omitempty"`
	SlotDuration      *int            `json:"slot_duration,omitempty"`
	YearsOfExperience *int            `json:"years_of_experience,omitempty"`
	Bio               *string         `json:"bio,omitempty"`
	LanguagesSpoken   []string        `json:"languages_spoken,omitempty"`
}

func (h *DoctorHandler) UpdateDoctorProfile(c *fiber.Ctx) error {

	// Get the doctor ID from URL parameter
	doctorID := c.Params("id")
	if doctorID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor ID is required"})
	}

	// Validate UUID format
	doctorUUID, err := uuid.Parse(doctorID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid doctor ID format"})
	}

	var updateData DoctorProfileUpdate
	if err := c.BodyParser(&updateData); err != nil {
		h.logger.Error("failed to parse update data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	// Check if any fields are provided
	if updateData.Username == nil && updateData.Name == nil && updateData.Mobile == nil &&
		updateData.BloodGroup == nil && updateData.Location == nil && updateData.Address == nil &&
		updateData.IMRNumber == nil && updateData.Age == nil && updateData.Specialization == nil &&
		updateData.IsActive == nil && updateData.Qualification == nil && updateData.SlotDuration == nil &&
		updateData.YearsOfExperience == nil && updateData.Bio == nil && len(updateData.LanguagesSpoken) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "No fields provided for update"})
	}

	// Validate provided fields
	if err := h.validateDoctorProfileUpdateFields(&updateData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(c.Context()); rollbackErr != nil {
				h.logger.Error("failed to rollback transaction", zap.Error(rollbackErr))
			}
		}
	}()

	userID := doctorUUID

	// Handle username uniqueness check if username is being updated
	if updateData.Username != nil {
		var currentUsername string
		err = tx.QueryRow(c.Context(),
			"SELECT username FROM users WHERE user_id = $1",
			userID).Scan(&currentUsername)
		if err != nil {
			h.logger.Error("failed to get current username", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
		}

		// If username is changing, check if the new username already exists (case-insensitive)
		if !strings.EqualFold(*updateData.Username, currentUsername) {
			var usernameExists bool
			err = tx.QueryRow(c.Context(),
				"SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) AND user_id != $2)",
				*updateData.Username, userID).Scan(&usernameExists)
			if err != nil {
				h.logger.Error("failed to check username uniqueness", zap.Error(err))
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
			}

			if usernameExists {
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
			}
		}
	}

	// Check if doctor record exists
	var doctorExists bool
	err = tx.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM doctors WHERE doctor_id = $1)",
		userID).Scan(&doctorExists)
	if err != nil {
		h.logger.Error("failed to check doctor existence", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Update users table with dynamic SQL
	if hasUserFields(&updateData) {
		userSQL, userArgs := buildUserUpdateSQL(&updateData, userID)
		userResult, err := tx.Exec(c.Context(), userSQL, userArgs...)
		if err != nil {
			// Check for constraint violations
			if strings.Contains(err.Error(), "users_username_key") || strings.Contains(err.Error(), "duplicate key") {
				h.logger.Error("username already exists", zap.Error(err))
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
			}
			h.logger.Error("failed to update user profile", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update profile"})
		}

		userRowsAffected := userResult.RowsAffected()
		h.logger.Info("Users table update", zap.Int64("rowsAffected", userRowsAffected))

		if userRowsAffected == 0 {
			h.logger.Error("no user rows affected - user might not exist", zap.String("user_id", userID.String()))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
	}

	// Handle doctor table update/insert with dynamic SQL
	if hasDoctorFields(&updateData) {
		var doctorResult pgconn.CommandTag
		if !doctorExists {
			// For new doctor records, we need all required fields
			if !hasRequiredDoctorFields(&updateData) {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Missing required fields for new doctor profile",
				})
			}
			doctorSQL, doctorArgs := buildDoctorInsertSQL(&updateData, userID)
			doctorResult, err = tx.Exec(c.Context(), doctorSQL, doctorArgs...)
		} else {
			// Update existing doctor record
			doctorSQL, doctorArgs := buildDoctorUpdateSQL(&updateData, userID)
			doctorResult, err = tx.Exec(c.Context(), doctorSQL, doctorArgs...)
		}

		if err != nil {
			h.logger.Error("failed to update/insert doctor profile", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update doctor profile"})
		}

		doctorRowsAffected := doctorResult.RowsAffected()
		h.logger.Info("Doctor profile updated/inserted", zap.Int64("rowsAffected", doctorRowsAffected))
	}

	// Commit the transaction
	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	committed = true

	h.logger.Info("Profile update completed successfully", zap.String("userID", userID.String()))

	return c.JSON(fiber.Map{
		"message":   "Doctor profile updated successfully",
		"doctor_id": userID.String(),
	})
}

// Helper functions for building dynamic SQL queries

func hasUserFields(updateData *DoctorProfileUpdate) bool {
	return updateData.Username != nil || updateData.Name != nil || updateData.Mobile != nil ||
		updateData.BloodGroup != nil || updateData.Location != nil || updateData.Address != nil
}

func hasDoctorFields(updateData *DoctorProfileUpdate) bool {
	return updateData.Name != nil || updateData.IMRNumber != nil || updateData.Age != nil ||
		updateData.Specialization != nil || updateData.IsActive != nil || updateData.Qualification != nil ||
		updateData.SlotDuration != nil || updateData.YearsOfExperience != nil || updateData.Bio != nil ||
		len(updateData.LanguagesSpoken) > 0
}

func hasRequiredDoctorFields(updateData *DoctorProfileUpdate) bool {
	// Define which fields are required for a new doctor record
	return updateData.Name != nil && updateData.Age != nil && updateData.Specialization != nil
}

func buildUserUpdateSQL(updateData *DoctorProfileUpdate, userID uuid.UUID) (string, []interface{}) {
	var setParts []string
	var args []interface{}
	argIndex := 1

	if updateData.Username != nil {
		setParts = append(setParts, fmt.Sprintf("username = $%d", argIndex))
		args = append(args, *updateData.Username)
		argIndex++
	}
	if updateData.Name != nil {
		setParts = append(setParts, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *updateData.Name)
		argIndex++
	}
	if updateData.Mobile != nil {
		setParts = append(setParts, fmt.Sprintf("mobile = $%d", argIndex))
		args = append(args, *updateData.Mobile)
		argIndex++
	}
	if updateData.BloodGroup != nil {
		setParts = append(setParts, fmt.Sprintf("blood_group = $%d", argIndex))
		args = append(args, *updateData.BloodGroup)
		argIndex++
	}
	if updateData.Location != nil {
		setParts = append(setParts, fmt.Sprintf("location = $%d", argIndex))
		args = append(args, *updateData.Location)
		argIndex++
	}
	if updateData.Address != nil {
		setParts = append(setParts, fmt.Sprintf("address = $%d", argIndex))
		args = append(args, *updateData.Address)
		argIndex++
	}

	sql := fmt.Sprintf("UPDATE users SET %s WHERE user_id = $%d", strings.Join(setParts, ", "), argIndex)
	args = append(args, userID)

	return sql, args
}

func buildDoctorUpdateSQL(updateData *DoctorProfileUpdate, userID uuid.UUID) (string, []interface{}) {
	var setParts []string
	var args []interface{}
	argIndex := 1

	if updateData.Name != nil {
		setParts = append(setParts, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *updateData.Name)
		argIndex++
	}
	if updateData.IMRNumber != nil {
		setParts = append(setParts, fmt.Sprintf("imr_number = $%d", argIndex))
		args = append(args, *updateData.IMRNumber)
		argIndex++
	}
	if updateData.Age != nil {
		setParts = append(setParts, fmt.Sprintf("age = $%d", argIndex))
		args = append(args, *updateData.Age)
		argIndex++
	}
	if updateData.Specialization != nil {
		specializationJSON, _ := json.Marshal(*updateData.Specialization)
		setParts = append(setParts, fmt.Sprintf("specialization = $%d", argIndex))
		args = append(args, specializationJSON)
		argIndex++
	}
	if updateData.IsActive != nil {
		setParts = append(setParts, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *updateData.IsActive)
		argIndex++
	}
	if updateData.Qualification != nil {
		setParts = append(setParts, fmt.Sprintf("qualification = $%d", argIndex))
		args = append(args, *updateData.Qualification)
		argIndex++
	}
	if updateData.SlotDuration != nil {
		setParts = append(setParts, fmt.Sprintf("slot_duration = $%d", argIndex))
		args = append(args, *updateData.SlotDuration)
		argIndex++
	}
	if updateData.YearsOfExperience != nil {
		setParts = append(setParts, fmt.Sprintf("years_of_experience = $%d", argIndex))
		args = append(args, *updateData.YearsOfExperience)
		argIndex++
	}
	if updateData.Bio != nil {
		setParts = append(setParts, fmt.Sprintf("bio = $%d", argIndex))
		args = append(args, *updateData.Bio)
		argIndex++
	}
	if len(updateData.LanguagesSpoken) > 0 {
		languagesJSON, _ := json.Marshal(updateData.LanguagesSpoken)
		setParts = append(setParts, fmt.Sprintf("languages_spoken = $%d", argIndex))
		args = append(args, languagesJSON)
		argIndex++
	}

	sql := fmt.Sprintf("UPDATE doctors SET %s WHERE doctor_id = $%d", strings.Join(setParts, ", "), argIndex)
	args = append(args, userID)

	return sql, args
}

func buildDoctorInsertSQL(updateData *DoctorProfileUpdate, userID uuid.UUID) (string, []interface{}) {
	var columns []string
	var placeholders []string
	var args []interface{}
	argIndex := 1

	// Always include doctor_id
	columns = append(columns, "doctor_id")
	placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
	args = append(args, userID)
	argIndex++

	// Add fields that are provided
	if updateData.Name != nil {
		columns = append(columns, "name")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, *updateData.Name)
		argIndex++
	}
	if updateData.IMRNumber != nil {
		columns = append(columns, "imr_number")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, *updateData.IMRNumber)
		argIndex++
	}
	if updateData.Age != nil {
		columns = append(columns, "age")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, *updateData.Age)
		argIndex++
	}
	if updateData.Specialization != nil {
		specializationJSON, _ := json.Marshal(*updateData.Specialization)
		columns = append(columns, "specialization")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, specializationJSON)
		argIndex++
	}
	if updateData.IsActive != nil {
		columns = append(columns, "is_active")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, *updateData.IsActive)
		argIndex++
	}
	if updateData.Qualification != nil {
		columns = append(columns, "qualification")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, *updateData.Qualification)
		argIndex++
	}
	if updateData.SlotDuration != nil {
		columns = append(columns, "slot_duration")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, *updateData.SlotDuration)
		argIndex++
	}
	if updateData.YearsOfExperience != nil {
		columns = append(columns, "years_of_experience")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, *updateData.YearsOfExperience)
		argIndex++
	}
	if updateData.Bio != nil {
		columns = append(columns, "bio")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, *updateData.Bio)
		argIndex++
	}
	if len(updateData.LanguagesSpoken) > 0 {
		languagesJSON, _ := json.Marshal(updateData.LanguagesSpoken)
		columns = append(columns, "languages_spoken")
		placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
		args = append(args, languagesJSON)
		argIndex++
	}

	sql := fmt.Sprintf("INSERT INTO doctors (%s) VALUES (%s)",
		strings.Join(columns, ", "), strings.Join(placeholders, ", "))

	return sql, args
}

// You'll also need to implement this validation function
func (h *DoctorHandler) validateDoctorProfileUpdateFields(updateData *DoctorProfileUpdate) error {
	// Add your validation logic here for individual fields
	// Example validations:

	if updateData.Username != nil && *updateData.Username == "" {
		return errors.New("username cannot be empty")
	}

	if updateData.Name != nil && *updateData.Name == "" {
		return errors.New("name cannot be empty")
	}

	if updateData.Age != nil && (*updateData.Age < 18 || *updateData.Age > 100) {
		return errors.New("age must be between 18 and 100")
	}

	if updateData.SlotDuration != nil && *updateData.SlotDuration <= 0 {
		return errors.New("slot duration must be positive")
	}

	if updateData.YearsOfExperience != nil && *updateData.YearsOfExperience < 0 {
		return errors.New("years of experience cannot be negative")
	}

	// Add more validation as needed
	return nil
}

// Helper function to validate schedule data
func validateScheduleData(schedule *DoctorSchedule) error {
	if schedule.DoctorID == "" {
		return fmt.Errorf("doctor ID is required")
	}
	if schedule.Weekday == "" {
		return fmt.Errorf("weekday is required")
	}
	if schedule.StartTime == "" {
		return fmt.Errorf("start time is required")
	}
	if schedule.EndTime == "" {
		return fmt.Errorf("end time is required")
	}

	// Validate weekday
	validWeekdays := []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}
	isValidWeekday := false
	for _, day := range validWeekdays {
		if schedule.Weekday == day {
			isValidWeekday = true
			break
		}
	}
	if !isValidWeekday {
		return fmt.Errorf("invalid weekday: %s", schedule.Weekday)
	}

	// Validate time format
	_, err := time.Parse("15:04", schedule.StartTime)
	if err != nil {
		return fmt.Errorf("invalid start time format. Use HH:MM (24-hour format)")
	}
	_, err = time.Parse("15:04", schedule.EndTime)
	if err != nil {
		return fmt.Errorf("invalid end time format. Use HH:MM (24-hour format)")
	}

	// Validate start time is before end time
	startTime, _ := time.Parse("15:04", schedule.StartTime)
	endTime, _ := time.Parse("15:04", schedule.EndTime)
	if !startTime.Before(endTime) {
		return fmt.Errorf("start time must be before end time")
	}

	return nil
}

// Helper function to calculate next occurrence of a weekday
func getNextWeekdayDate(targetWeekday string) (time.Time, error) {
	weekdays := map[string]time.Weekday{
		"Monday":    time.Monday,
		"Tuesday":   time.Tuesday,
		"Wednesday": time.Wednesday,
		"Thursday":  time.Thursday,
		"Friday":    time.Friday,
		"Saturday":  time.Saturday,
		"Sunday":    time.Sunday,
	}

	targetDay, exists := weekdays[targetWeekday]
	if !exists {
		return time.Time{}, fmt.Errorf("invalid weekday: %s", targetWeekday)
	}

	now := time.Now()
	today := now.Weekday()
	daysUntilTarget := (int(targetDay) - int(today) + 7) % 7
	if daysUntilTarget == 0 { // Today is the target weekday
		nextWeek := now.AddDate(0, 0, 7)
		return time.Date(nextWeek.Year(), nextWeek.Month(), nextWeek.Day(), 0, 0, 0, 0, time.Local), nil
	}

	nextOccurrence := now.AddDate(0, 0, daysUntilTarget)
	return time.Date(nextOccurrence.Year(), nextOccurrence.Month(), nextOccurrence.Day(), 0, 0, 0, 0, time.Local), nil
}

// GenerateSlots creates appointment slots based on a doctor's schedule
func (h *DoctorHandler) GenerateSlots(ctx context.Context, doctorID uuid.UUID, orgID string, weekday string, startTime, endTime time.Time, slotDuration int) error {
	if slotDuration <= 0 {
		return fmt.Errorf("invalid slot duration")
	}

	// Get doctor's slot duration if not specified
	if slotDuration == 0 {
		err := h.pgPool.QueryRow(ctx,
			`SELECT slot_duration FROM doctors WHERE doctor_id = $1`,
			doctorID).Scan(&slotDuration)
		if err != nil {
			h.logger.Error("failed to get doctor's slot duration", zap.Error(err))
			return err
		}
	}

	// Calculate how many slots we need to generate
	slotDurationMinutes := time.Duration(slotDuration) * time.Minute
	startDateTime := time.Date(0, 1, 1, startTime.Hour(), startTime.Minute(), 0, 0, time.UTC)
	endDateTime := time.Date(0, 1, 1, endTime.Hour(), endTime.Minute(), 0, 0, time.UTC)

	// Generate slots for the next 4 weeks (or customize as needed)
	for weekOffset := 0; weekOffset < 4; weekOffset++ {
		// Get next occurrence of this weekday
		baseDate, err := getNextWeekdayDate(weekday)
		if err != nil {
			h.logger.Error("failed to calculate next weekday", zap.Error(err))
			return err
		}

		// Add weeks to get future dates
		slotDate := baseDate.AddDate(0, 0, 7*weekOffset)

		// Start a transaction for batch insert
		tx, err := h.pgPool.Begin(ctx)
		if err != nil {
			h.logger.Error("failed to start transaction", zap.Error(err))
			return err
		}

		defer func() {
			if err != nil {
				tx.Rollback(ctx)
			}
		}()

		// Generate slots for this date
		for currentTime := startDateTime; currentTime.Add(slotDurationMinutes).Before(endDateTime) || currentTime.Add(slotDurationMinutes).Equal(endDateTime); currentTime = currentTime.Add(slotDurationMinutes) {
			slotStartTime := fmt.Sprintf("%02d:%02d", currentTime.Hour(), currentTime.Minute())
			slotEndTime := fmt.Sprintf("%02d:%02d", currentTime.Add(slotDurationMinutes).Hour(), currentTime.Add(slotDurationMinutes).Minute())

			// Check if slot already exists
			var exists bool
			err = h.pgPool.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM doctorslots WHERE doctor_id = $1 AND organization_id = $2 AND slot_date = $3 AND slot_start_time = $4)`,
				doctorID, orgID, slotDate, slotStartTime).Scan(&exists)
			if err != nil {
				h.logger.Error("failed to check if slot exists", zap.Error(err))
				return err
			}

			if !exists {
				// Insert the new slot
				_, err = tx.Exec(ctx,
					`INSERT INTO doctorslots (doctor_id, organization_id, slot_date, slot_start_time, slot_end_time, weekday, is_booked, is_active) 
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
					doctorID, orgID, slotDate, slotStartTime, slotEndTime, weekday, false, true)
				if err != nil {
					h.logger.Error("failed to insert slot", zap.Error(err))
					return err
				}
			}
		}

		// Commit the transaction
		err = tx.Commit(ctx)
		if err != nil {
			h.logger.Error("failed to commit transaction", zap.Error(err))
			return err
		}
	}

	return nil
}

// DeleteSlots removes all slots for a specific doctor's schedule
func (h *DoctorHandler) DeleteSlots(ctx context.Context, doctorID uuid.UUID, orgID string, weekday string) error {
	// Get the next 4 occurrences of this weekday (or customize as needed)
	for weekOffset := 0; weekOffset < 4; weekOffset++ {
		// Get next occurrence of this weekday
		baseDate, err := getNextWeekdayDate(weekday)
		if err != nil {
			h.logger.Error("failed to calculate next weekday", zap.Error(err))
			return err
		}

		// Add weeks to get future dates
		slotDate := baseDate.AddDate(0, 0, 7*weekOffset)

		// Delete all slots for this doctor, organization, weekday, and date
		// Only delete slots that aren't booked
		_, err = h.pgPool.Exec(ctx,
			`DELETE FROM doctorslots 
			WHERE doctor_id = $1 
			AND organization_id = $2 
			AND weekday = $3 
			AND slot_date = $4
			AND is_booked = FALSE`,
			doctorID, orgID, weekday, slotDate)
		if err != nil {
			h.logger.Error("failed to delete slots", zap.Error(err))
			return err
		}
	}

	return nil
}

// CreateDoctorSchedule adds a new doctor's schedule and generates slots
func (h *DoctorHandler) CreateDoctorSchedule(c *fiber.Ctx) error {
	// Get the authenticated user's ID
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println(authID)
	// Get organization ID from context
	orgID := c.Get("X-Organization-ID")
	if orgID == "" {
		h.logger.Error("organization ID not found in request headers")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required"})
	}

	// Parse request body
	var scheduleData struct {
		DoctorID  string `json:"doctorID"`
		Weekday   string `json:"weekday"`
		StartTime string `json:"startTime"`
		EndTime   string `json:"endTime"`
		IsActive  bool   `json:"isActive"`
	}

	if err := c.BodyParser(&scheduleData); err != nil {
		h.logger.Error("failed to parse schedule data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	// Validate weekday
	if scheduleData.Weekday == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Weekday is required"})
	}

	// Validate doctor ID
	if scheduleData.DoctorID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor ID is required"})
	}

	// Parse the doctor ID to UUID
	doctorID, err := uuid.Parse(scheduleData.DoctorID)
	if err != nil {
		h.logger.Error("invalid doctor ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid doctor ID format"})
	}

	// Check if doctor exists and get slot duration
	var doctorExists bool
	var slotDuration int
	err = h.pgPool.QueryRow(c.Context(),
		`SELECT EXISTS(SELECT 1 FROM doctors WHERE doctor_id = $1), 
		(SELECT slot_duration FROM doctors WHERE doctor_id = $1)`,
		doctorID).Scan(&doctorExists, &slotDuration)
	if err != nil {
		h.logger.Error("failed to check if doctor exists", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	if !doctorExists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor not found"})
	}

	// Check if slot duration is set
	if slotDuration <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor's slot duration is not set. Please update the doctor first."})
	}

	// Check if schedule already exists
	var exists bool
	err = h.pgPool.QueryRow(c.Context(),
		`SELECT EXISTS(SELECT 1 FROM doctorshifts WHERE doctor_id = $1 AND organization_id = $2 AND weekday = $3)`,
		doctorID, orgID, scheduleData.Weekday).Scan(&exists)
	if err != nil {
		h.logger.Error("failed to check if schedule exists", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	if exists {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Schedule already exists for this day and organization"})
	}

	// Parse time strings
	layout := "15:04" // Hour:Minute format

	// Parse start time
	startTime, err := time.Parse(layout, scheduleData.StartTime)
	if err != nil {
		h.logger.Error("failed to parse start time", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid start time format. Use HH:MM format."})
	}

	// Parse end time
	endTime, err := time.Parse(layout, scheduleData.EndTime)
	if err != nil {
		h.logger.Error("failed to parse end time", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid end time format. Use HH:MM format."})
	}

	// Validate start time is before end time
	if !startTime.Before(endTime) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Start time must be before end time"})
	}

	// Start a transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to start transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Defer rollback in case anything fails
	defer func() {
		if err != nil {
			tx.Rollback(c.Context())
		}
	}()

	// Insert new schedule
	_, err = tx.Exec(c.Context(),
		`INSERT INTO doctorshifts (doctor_id, organization_id, weekday, starttime, endtime, isactive)
         VALUES ($1, $2, $3, $4, $5, $6)`,
		doctorID, orgID, scheduleData.Weekday, startTime, endTime, scheduleData.IsActive)
	if err != nil {
		h.logger.Error("failed to create doctor schedule", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create schedule"})
	}

	// Commit the transaction
	err = tx.Commit(c.Context())
	if err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// If the schedule is active, generate slots
	if scheduleData.IsActive {
		err = h.GenerateSlots(c.Context(), doctorID, orgID, scheduleData.Weekday, startTime, endTime, slotDuration)
		if err != nil {
			h.logger.Error("failed to generate slots", zap.Error(err))
			// Don't return error here, just log it. The schedule was created successfully.
		}
	}

	// Return success response
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":        "Schedule created successfully",
		"doctorID":       doctorID,
		"organizationID": orgID,
		"weekday":        scheduleData.Weekday,
	})
}

// UpdateDoctorSchedule updates a doctor's schedule and regenerates slots
func (h *DoctorHandler) UpdateDoctorSchedule(c *fiber.Ctx) error {
	// Get the authenticated user's ID
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println(authID)
	// Get organization ID from context
	orgID := c.Get("X-Organization-ID")
	if orgID == "" {
		h.logger.Error("organization ID not found in request headers")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required"})
	}

	// Parse request body
	var scheduleData struct {
		DoctorID  string `json:"doctorID"`
		Weekday   string `json:"weekday"`
		StartTime string `json:"startTime"`
		EndTime   string `json:"endTime"`
		IsActive  bool   `json:"isActive"`
	}

	if err := c.BodyParser(&scheduleData); err != nil {
		h.logger.Error("failed to parse schedule data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	// Validate schedule data
	if err := validateScheduleData(&DoctorSchedule{
		DoctorID:  scheduleData.DoctorID,
		Weekday:   scheduleData.Weekday,
		StartTime: scheduleData.StartTime,
		EndTime:   scheduleData.EndTime,
		IsActive:  scheduleData.IsActive,
	}); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Parse the doctor ID to UUID
	doctorID, err := uuid.Parse(scheduleData.DoctorID)
	if err != nil {
		h.logger.Error("invalid doctor ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid doctor ID format"})
	}

	// Check if doctor exists and get slot duration
	var doctorExists bool
	var slotDuration int
	err = h.pgPool.QueryRow(c.Context(),
		`SELECT EXISTS(SELECT 1 FROM doctors WHERE doctor_id = $1), 
		(SELECT slot_duration FROM doctors WHERE doctor_id = $1)`,
		doctorID).Scan(&doctorExists, &slotDuration)
	if err != nil {
		h.logger.Error("failed to check if doctor exists", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	if !doctorExists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor not found"})
	}

	// Check if slot duration is set
	if slotDuration <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor's slot duration is not set. Please update the doctor first."})
	}

	// Parse time strings
	layout := "15:04" // Hour:Minute format

	// Parse start time
	startTime, err := time.Parse(layout, scheduleData.StartTime)
	if err != nil {
		h.logger.Error("failed to parse start time", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid start time format. Use HH:MM format."})
	}

	// Parse end time
	endTime, err := time.Parse(layout, scheduleData.EndTime)
	if err != nil {
		h.logger.Error("failed to parse end time", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid end time format. Use HH:MM format."})
	}

	// Start a transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to start transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Defer rollback in case anything fails
	defer func() {
		if err != nil {
			tx.Rollback(c.Context())
		}
	}()

	// Check if the schedule exists (to know if this is an insert or update)
	var existingSchedule struct {
		exists   bool
		isActive bool
	}

	err = h.pgPool.QueryRow(c.Context(),
		`SELECT EXISTS(SELECT 1 FROM doctorshifts WHERE doctor_id = $1 AND organization_id = $2 AND weekday = $3),
		(SELECT isactive FROM doctorshifts WHERE doctor_id = $1 AND organization_id = $2 AND weekday = $3)`,
		doctorID, orgID, scheduleData.Weekday).Scan(&existingSchedule.exists, &existingSchedule.isActive)
	if err != nil {
		// If error is because schedule doesn't exist, set exists to false
		existingSchedule.exists = false
	}

	// Update or insert the schedule
	_, err = tx.Exec(c.Context(),
		`INSERT INTO doctorshifts (doctor_id, organization_id, weekday, starttime, endtime, isactive)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (doctor_id, weekday, organization_id)
		DO UPDATE SET starttime = $4, endtime = $5, isactive = $6`,
		doctorID, orgID, scheduleData.Weekday, startTime, endTime, scheduleData.IsActive)
	if err != nil {
		h.logger.Error("failed to update doctor schedule", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update schedule"})
	}

	// Commit the transaction
	err = tx.Commit(c.Context())
	if err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Handle slots based on schedule changes
	if existingSchedule.exists {
		// If schedule was active but is now inactive, delete future slots
		if existingSchedule.isActive && !scheduleData.IsActive {
			err = h.DeleteSlots(c.Context(), doctorID, orgID, scheduleData.Weekday)
			if err != nil {
				h.logger.Error("failed to delete slots", zap.Error(err))
				// Don't return error, just log it
			}
		} else if scheduleData.IsActive {
			// If schedule is active, regenerate slots
			// First delete existing future slots
			err = h.DeleteSlots(c.Context(), doctorID, orgID, scheduleData.Weekday)
			if err != nil {
				h.logger.Error("failed to delete existing slots", zap.Error(err))
				// Don't return error, just log it
			}

			// Then generate new slots
			err = h.GenerateSlots(c.Context(), doctorID, orgID, scheduleData.Weekday, startTime, endTime, slotDuration)
			if err != nil {
				h.logger.Error("failed to generate slots", zap.Error(err))
				// Don't return error, just log it
			}
		}
	} else if scheduleData.IsActive {
		// New schedule that is active, generate slots
		err = h.GenerateSlots(c.Context(), doctorID, orgID, scheduleData.Weekday, startTime, endTime, slotDuration)
		if err != nil {
			h.logger.Error("failed to generate slots", zap.Error(err))
			// Don't return error, just log it
		}
	}

	return c.JSON(fiber.Map{"message": "Schedule updated successfully"})
}

func (h *DoctorHandler) CreateDoctorFees(c *fiber.Ctx) error {
	// Get organization ID from headers
	orgID := c.Get("X-Organization-ID")
	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required"})
	}

	// Log request body for debugging
	h.logger.Info("Received doctor fees request",
		zap.String("body", string(c.Body())),
		zap.String("orgID", orgID))

	// Parse request body
	var feesData struct {
		DoctorID      string `json:"doctorID"`
		RecurringFees int    `json:"recurringFees"`
		DefaultFees   int    `json:"defaultFees"`
		EmergencyFees int    `json:"emergencyFees"`
	}

	if err := c.BodyParser(&feesData); err != nil {
		h.logger.Error("failed to parse request body", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
	}

	// Log parsed data
	h.logger.Info("Parsed doctor fees data",
		zap.String("doctorID", feesData.DoctorID),
		zap.Int("recurringFees", feesData.RecurringFees),
		zap.Int("defaultFees", feesData.DefaultFees),
		zap.Int("emergencyFees", feesData.EmergencyFees))

	// Parse the doctor ID string to UUID
	doctorID, err := uuid.Parse(feesData.DoctorID)
	if err != nil {
		h.logger.Warn("invalid doctor ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":      "Invalid doctor ID format",
			"receivedID": feesData.DoctorID,
		})
	}

	// Just check if the doctor exists first
	var exists bool
	err = h.pgPool.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM doctors WHERE doctor_id = $1)",
		doctorID).Scan(&exists)
	if err != nil {
		h.logger.Error("failed to check if doctor exists", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !exists {
		h.logger.Warn("doctor not found",
			zap.String("doctorID", feesData.DoctorID),
			zap.String("orgID", orgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":          "Doctor not found",
			"doctorID":       feesData.DoctorID,
			"organizationID": orgID,
		})
	}

	// Check if fees already exist for this doctor in this organization
	err = h.pgPool.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM doctor_fees WHERE doctor_id = $1 AND organization_id = $2)",
		doctorID, orgID).Scan(&exists)
	if err != nil {
		h.logger.Error("failed to check if fees exist", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if exists {
		h.logger.Warn("fees already exist for this doctor",
			zap.String("doctorID", feesData.DoctorID),
			zap.String("orgID", orgID))
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":          "Fees already exist for this doctor",
			"doctorID":       feesData.DoctorID,
			"organizationID": orgID,
		})
	}

	// Insert new fees
	_, err = h.pgPool.Exec(c.Context(),
		`INSERT INTO doctor_fees
        (doctor_id, organization_id, recurring_fees, default_fees, emergency_fees, created_at)
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`,
		doctorID, orgID, feesData.RecurringFees, feesData.DefaultFees, feesData.EmergencyFees)
	if err != nil {
		h.logger.Error("failed to create doctor fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create fees"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":        "Fees created successfully",
		"doctorID":       feesData.DoctorID,
		"organizationID": orgID,
	})
}

// UpdateDoctorFees adds or updates the doctor's fees structure
func (h *DoctorHandler) UpdateDoctorFees(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println(authID)
	// Get organization ID from request header
	orgID := c.Get("X-Organization-ID")
	if orgID == "" {
		h.logger.Error("organization ID not found in request headers")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required"})
	}

	// Parse request body
	var feesData struct {
		DoctorID       string `json:"doctorID"`
		OrganizationID string `json:"organizationID"`
		RecurringFees  int    `json:"recurringFees"`
		DefaultFees    int    `json:"defaultFees"`
		EmergencyFees  int    `json:"emergencyFees"`
	}

	if err := c.BodyParser(&feesData); err != nil {
		h.logger.Error("failed to parse fees data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	// Basic validation
	if feesData.RecurringFees < 0 || feesData.DefaultFees < 0 || feesData.EmergencyFees < 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Fees cannot be negative"})
	}

	// Get the doctor ID from the request body if provided, otherwise use the authenticated user
	var doctorID uuid.UUID
	var doctorName string

	if feesData.DoctorID != "" {
		// If doctor ID is provided in the request, use it (after validation)
		// This allows admins to set fees for other doctors
		var err error
		doctorID, err = uuid.Parse(feesData.DoctorID)
		if err != nil {
			h.logger.Error("invalid doctor ID format", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid doctor ID format"})
		}

		// Check if the doctor exists
		err = h.pgPool.QueryRow(c.Context(),
			"SELECT name FROM doctors WHERE doctor_id = $1",
			doctorID).Scan(&doctorName)
		if err != nil {
			if err == pgx.ErrNoRows {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Doctor not found"})
			}
			h.logger.Error("failed to check if doctor exists", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
		}
	} else {
		// If no doctor ID provided, use the authenticated user
		err = h.pgPool.QueryRow(c.Context(),
			"SELECT d.doctor_id, d.name FROM users u JOIN doctors d ON u.user_id = d.doctor_id WHERE u.auth_id = $1",
			authID).Scan(&doctorID, &doctorName)
		if err != nil {
			h.logger.Error("failed to get doctor ID and name", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
		}
	}

	// Use the organization ID from the header as the primary one
	// (feesData.OrganizationID is just a backup, prefer the header)
	if orgID == "" && feesData.OrganizationID != "" {
		orgID = feesData.OrganizationID
	}

	// Check if organization exists
	var orgExists bool
	err = h.pgPool.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM organizations WHERE organization_id = $1)",
		orgID).Scan(&orgExists)
	if err != nil {
		h.logger.Error("failed to check if organization exists", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	if !orgExists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization not found"})
	}

	h.logger.Info("Updating doctor fees",
		zap.String("doctor_id", doctorID.String()),
		zap.String("org_id", orgID),
		zap.Int("recurring_fees", feesData.RecurringFees),
		zap.Int("default_fees", feesData.DefaultFees),
		zap.Int("emergency_fees", feesData.EmergencyFees))

	// Upsert the doctor fees record
	_, err = h.pgPool.Exec(c.Context(),
		`INSERT INTO doctor_fees (doctor_id, organization_id, recurring_fees, default_fees, emergency_fees, created_at)
         VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
         ON CONFLICT (doctor_id, organization_id)
         DO UPDATE SET recurring_fees = $3, default_fees = $4, emergency_fees = $5, created_at = CURRENT_TIMESTAMP`,
		doctorID, orgID, feesData.RecurringFees, feesData.DefaultFees, feesData.EmergencyFees)
	if err != nil {
		h.logger.Error("failed to update doctor fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update fees"})
	}

	// Return the successful response with doctor name
	return c.JSON(fiber.Map{
		"message": "Fees updated successfully",
		"data": fiber.Map{
			"doctorID":       doctorID,
			"doctorName":     doctorName,
			"organizationID": orgID,
			"recurringFees":  feesData.RecurringFees,
			"defaultFees":    feesData.DefaultFees,
			"emergencyFees":  feesData.EmergencyFees,
			"updatedAt":      time.Now().Format(time.RFC3339),
		},
	})
}

// validateDoctorProfileUpdate validates the doctor profile update data
func (h *DoctorHandler) validateDoctorProfileUpdate(profile *DoctorProfile) error {
	validations := []struct {
		condition bool
		message   string
	}{
		{profile.Username != "" && (len(profile.Username) < 3 || len(profile.Username) > 30),
			"username must be between 3 and 30 characters"},
		{profile.Username != "" && !regexp.MustCompile(`^[a-zA-Z0-9_.]+$`).MatchString(profile.Username),
			"username can only contain letters, numbers, underscores, and periods"},
		{len(profile.Name) > 100,
			"name must not exceed 100 characters"},
		{profile.Mobile != "" && !regexp.MustCompile(`^\+?[0-9]{10,15}$`).MatchString(profile.Mobile),
			"invalid mobile number format"},
		{profile.BloodGroup != "" && !map[string]bool{"A+": true, "A-": true, "B+": true, "B-": true, "O+": true, "O-": true, "AB+": true, "AB-": true}[profile.BloodGroup],
			"invalid blood group"},
		{len(profile.Location) > 100,
			"location must not exceed 100 characters"},
		{len(profile.Address) > 500,
			"address must not exceed 500 characters"},
		{profile.IMRNumber != "" && len(profile.IMRNumber) > 30,
			"IMR number must not exceed 30 characters"},
		{profile.Age < 18 || profile.Age > 100,
			"age must be between 18 and 100"},
		{len(profile.Specialization.Primary) > 100,
			"primary specialization must not exceed 100 characters"},
		{len(profile.Qualification) > 200,
			"qualification must not exceed 200 characters"},
		{profile.SlotDuration < 5 || profile.SlotDuration > 120,
			"slot duration must be between 5 and 120 minutes"},
	}

	for _, v := range validations {
		if v.condition {
			h.logger.Error("validation error", zap.String("error", v.message))
			return errors.New(v.message)
		}
	}

	// Validate secondary specializations and tags if they exist
	if len(profile.Specialization.Secondary) > 0 {
		for i, s := range profile.Specialization.Secondary {
			if len(s) > 100 {
				return errors.New("secondary specialization item must not exceed 100 characters")
			}
			if len(profile.Specialization.Secondary) > 10 {
				return errors.New("cannot have more than 10 secondary specializations")
			}
			// Check for duplicates
			for j := i + 1; j < len(profile.Specialization.Secondary); j++ {
				if s == profile.Specialization.Secondary[j] {
					return errors.New("duplicate secondary specialization found")
				}
			}
		}
	}

	if len(profile.Specialization.Tags) > 0 {
		if len(profile.Specialization.Tags) > 20 {
			return errors.New("cannot have more than 20 tags")
		}
		for i, tag := range profile.Specialization.Tags {
			if len(tag) > 50 {
				return errors.New("tag must not exceed 50 characters")
			}
			// Check for duplicates
			for j := i + 1; j < len(profile.Specialization.Tags); j++ {
				if tag == profile.Specialization.Tags[j] {
					return errors.New("duplicate tag found")
				}
			}
		}
	}

	return nil
}

// DeleteDoctorSchedule removes a doctor's schedule and associated slots
func (h *DoctorHandler) DeleteDoctorSchedule(c *fiber.Ctx) error {
	// Get the authenticated user's ID
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println(authID)

	// The schedule ID is expected to be in the format: doctor_id_weekday_org_organization_id
	compositeID := c.Params("id")
	if compositeID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Schedule ID is required"})
	}

	// Find the position of "_org_" in the composite ID
	orgMarkerPos := strings.Index(compositeID, "_org_")
	if orgMarkerPos == -1 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid schedule ID format: missing _org_ marker"})
	}

	// Split the part before "_org_" to get doctor_id and weekday
	beforeOrg := compositeID[:orgMarkerPos]
	parts := strings.Split(beforeOrg, "_")
	if len(parts) != 2 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":        "Invalid schedule ID format: expected doctor_id_weekday_org_organization_id",
			"received":     compositeID,
			"parsed_parts": parts,
		})
	}

	doctorIDStr := parts[0]
	weekday := parts[1]

	// Extract the organization ID (everything after "_org_", including the "org_" prefix)
	// Position after "_org_" marker (skip the underscore, keep "org_")
	organizationID := compositeID[orgMarkerPos+1:] // This will be "org_01JT7ZG469F30KMSG6BASYDQD3"

	// Parse the doctor ID to UUID
	doctorID, err := uuid.Parse(doctorIDStr)
	if err != nil {
		h.logger.Error("invalid doctor ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid doctor ID format"})
	}

	// Log for debugging
	h.logger.Debug("Deleting schedule",
		zap.String("compositeID", compositeID),
		zap.String("doctorID", doctorIDStr),
		zap.String("weekday", weekday),
		zap.String("organizationID", organizationID))

	// Start a transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to start transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Defer rollback in case anything fails
	defer func() {
		if err != nil {
			tx.Rollback(c.Context())
		}
	}()

	// First, delete all future slots associated with this schedule
	_, err = tx.Exec(c.Context(),
		`DELETE FROM doctorslots
		 WHERE doctor_id = $1
		 AND organization_id = $2
		 AND weekday = $3
		 AND slot_date >= CURRENT_DATE
		 AND is_booked = false`,
		doctorID, organizationID, weekday)
	if err != nil {
		h.logger.Error("failed to delete associated slots", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete associated slots"})
	}

	// Then delete the schedule
	result, err := tx.Exec(c.Context(),
		`DELETE FROM doctorshifts WHERE doctor_id = $1 AND weekday = $2 AND organization_id = $3`,
		doctorID, weekday, organizationID)
	if err != nil {
		h.logger.Error("failed to delete doctor schedule", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete schedule"})
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		// Rollback the transaction since no schedule was found
		tx.Rollback(c.Context())

		// Log what we're looking for vs what exists
		h.logger.Warn("Schedule not found",
			zap.String("doctorID", doctorID.String()),
			zap.String("weekday", weekday),
			zap.String("organizationID", organizationID))

		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Schedule not found",
			"searched_for": map[string]interface{}{
				"doctor_id":       doctorID.String(),
				"weekday":         weekday,
				"organization_id": organizationID,
			},
		})
	}

	// Commit the transaction
	err = tx.Commit(c.Context())
	if err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	return c.JSON(fiber.Map{
		"message":        "Schedule deleted successfully",
		"doctorID":       doctorID,
		"organizationID": organizationID,
		"weekday":        weekday,
	})
}

// DeleteDoctorFees deletes a doctor's fees for a specific organization
func (h *DoctorHandler) DeleteDoctorFees(c *fiber.Ctx) error {
	// Get composite ID from path parameter
	compositeIDParam := c.Params("id")
	if compositeIDParam == "" {
		h.logger.Error("composite ID not found in path parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Composite ID is required"})
	}

	// Parse the composite ID to extract doctor_id and organization_id
	// Expected format: doctor_id_org_organization_id
	parts := strings.Split(compositeIDParam, "_")
	if len(parts) < 3 {
		h.logger.Error("invalid composite ID format", zap.String("composite_id", compositeIDParam))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid composite ID format"})
	}

	// Extract doctor ID (first part)
	doctorIDStr := parts[0]
	doctorID, err := uuid.Parse(doctorIDStr)
	if err != nil {
		h.logger.Error("invalid doctor ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid doctor ID format"})
	}

	// Extract organization ID (everything after "org_")
	var orgID string
	orgIndex := -1
	for i, part := range parts {
		if part == "org" {
			orgIndex = i
			break
		}
	}

	if orgIndex == -1 || orgIndex+1 >= len(parts) {
		h.logger.Error("organization ID not found in composite ID", zap.String("composite_id", compositeIDParam))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID not found in composite ID"})
	}

	// Join all parts after "org" to handle organization IDs that might contain underscores
	orgID = strings.Join(parts[orgIndex+1:], "_")

	// Also check for organization ID in request header as fallback
	headerOrgID := c.Get("X-Organization-ID")
	if headerOrgID != "" && headerOrgID != orgID {
		h.logger.Warn("organization ID mismatch between composite ID and header",
			zap.String("composite_org_id", orgID),
			zap.String("header_org_id", headerOrgID))
		// Use the header org ID as it's more authoritative
		orgID = headerOrgID
	}

	h.logger.Info("Deleting doctor fees",
		zap.String("composite_id", compositeIDParam),
		zap.String("doctor_id", doctorID.String()),
		zap.String("org_id", orgID))

	// Verify doctor exists
	var doctorExists bool
	err = h.pgPool.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM doctors WHERE doctor_id = $1)", doctorID).Scan(&doctorExists)
	if err != nil {
		h.logger.Error("failed to check if doctor exists", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	if !doctorExists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Doctor not found"})
	}

	// Note: Skipping organization validation as organizations table doesn't exist
	// Organization ID is validated through authentication middleware

	// Execute DELETE using the composite primary key columns
	result, err := h.pgPool.Exec(c.Context(),
		`DELETE FROM doctor_fees WHERE doctor_id = $1 AND organization_id = $2`, doctorID, orgID)
	if err != nil {
		h.logger.Error("failed to delete doctor fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete doctor fees"})
	}

	// Check if any rows were actually deleted
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		h.logger.Warn("no doctor fees found to delete",
			zap.String("doctor_id", doctorID.String()),
			zap.String("org_id", orgID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "No doctor fees found for this doctor in this organization"})
	}

	h.logger.Info("Successfully deleted doctor fees",
		zap.String("doctor_id", doctorID.String()),
		zap.String("org_id", orgID),
		zap.Int64("rows_affected", rowsAffected))

	return c.JSON(fiber.Map{
		"message": "Doctor fees deleted successfully",
		"data": fiber.Map{
			"doctorID":       doctorID,
			"organizationID": orgID,
			"compositeID":    compositeIDParam,
		},
	})
}

// GetDoctorsByOrganization retrieves all doctors in the same organization
func (h *DoctorHandler) GetDoctorsByOrganization(c *fiber.Ctx) error {
	// Get organization ID from context
	orgID := c.Get("X-Organization-ID")
	if orgID == "" {
		h.logger.Error("organization ID not found in context")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required"})
	}

	// Verify user is authenticated
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("failed to get authentication ID", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	h.logger.Info("fetching doctors for organization",
		zap.String("orgID", orgID),
		zap.String("authID", authID))

	// Improved query with more efficient join and better field selection
	query := `
		SELECT
			d.doctor_id,
			u.auth_id,
			u.username,
			u.profile_pic,
			u.name,
			d.specialization,
			d.is_active,
			d.qualification,
			d.imr_number,
			d.slot_duration
		FROM
			doctors d
		INNER JOIN
			users u ON d.doctor_id = u.user_id
		INNER JOIN
			hospitals h ON u.hospital_id = h.hospital_id
		WHERE
			h.org_id = $1
		ORDER BY
			u.name ASC
	`

	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	rows, err := h.pgPool.Query(ctx, query, orgID)
	if err != nil {
		h.logger.Error("failed to fetch doctors", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch doctors",
		})
	}
	defer rows.Close()

	doctors := make([]map[string]interface{}, 0)
	for rows.Next() {
		var (
			doctorID           uuid.UUID
			authID             string
			username           sql.NullString
			profilePic         sql.NullString
			name               sql.NullString
			specializationJSON []byte
			isActive           bool
			qualification      sql.NullString
			imrNumber          sql.NullString
			slotDuration       sql.NullInt32
		)

		if err := rows.Scan(
			&doctorID,
			&authID,
			&username,
			&profilePic,
			&name,
			&specializationJSON,
			&isActive,
			&qualification,
			&imrNumber,
			&slotDuration,
		); err != nil {
			h.logger.Error("failed to scan doctor row", zap.Error(err))
			continue
		}

		// Parse specialization JSON
		var specialization Specialization
		if len(specializationJSON) > 0 {
			if err := json.Unmarshal(specializationJSON, &specialization); err != nil {
				h.logger.Error("failed to parse specialization JSON",
					zap.Error(err),
					zap.String("doctorID", doctorID.String()))
				specialization = Specialization{Primary: "Unknown"}
			}
		} else {
			specialization = Specialization{Primary: ""}
		}

		doctors = append(doctors, map[string]interface{}{
			"doctor_id":           doctorID,
			"auth_id":             authID,
			"username":            username.String,
			"profile_picture_url": profilePic.String,
			"name":                name.String,
			"specialization":      specialization,
			"is_active":           isActive,
			"qualification":       qualification.String,
			"imr_number":          imrNumber.String,
			"slot_duration":       slotDuration.Int32,
		})
	}

	if err := rows.Err(); err != nil {
		h.logger.Error("error during doctors rows scan", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process doctors data"})
	}

	h.logger.Info("successfully fetched doctors",
		zap.Int("count", len(doctors)),
		zap.String("orgID", orgID))

	return c.JSON(map[string]interface{}{
		"status": "success",
		"count":  len(doctors),
		"data":   doctors,
	})
}
