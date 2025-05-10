// doctor handler
package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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
}

type DoctorSchedule struct {
	DoctorID   string `json:"doctor_id"`
	HospitalID string `json:"hospital_id"`
	DoctorName string `json:"doctor_name"` // Add this field
	Weekday    string `json:"weekday"`
	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time"`
	IsActive   bool   `json:"is_active"`
}

type DoctorFees struct {
	DoctorID      uuid.UUID `json:"doctor_id"`
	HospitalID    uuid.UUID `json:"hospital_id"`
	DoctorName    string    `json:"doctor_name"`
	RecurringFees int       `json:"recurring_fees"`
	DefaultFees   int       `json:"default_fees"`
	EmergencyFees int       `json:"emergency_fees"`
	CreatedAt     string    `json:"created_at,omitempty"`
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

func (h *DoctorHandler) isUserDoctor(ctx context.Context, userID uuid.UUID) (bool, error) {
	var isDoctor bool
	err := h.pgPool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM doctors WHERE doctor_id = $1)", userID).Scan(&isDoctor)
	return isDoctor, err
}

func (h *DoctorHandler) checkHospitalExists(ctx context.Context, hospitalID uuid.UUID) (bool, error) {
	var exists bool
	err := h.pgPool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM hospitals WHERE id = $1)", hospitalID).Scan(&exists)
	return exists, err
}

func (h *DoctorHandler) getAuthID(c *fiber.Ctx) (string, error) {
	authID, ok := c.Locals("authID").(string)
	if !ok {
		return "", errors.New("user ID not found")
	}
	return authID, nil
}

// GetDoctorProfile retrieves the doctor's complete profile
func (h *DoctorHandler) GetDoctorProfile(c *fiber.Ctx) error {

	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	h.logger.Info("processing doctor profile request", zap.String("authID", authID), zap.Any("all_claims", c.Locals("claims")))

	// Get user from WorkOS
	workosUser, err := usermanagement.GetUser(c.Context(), usermanagement.GetUserOpts{User: authID})
	if err != nil {
		h.logger.Error("failed to fetch user from WorkOS", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user profile from authentication provider",
		})
	}

	// Get user ID directly from database
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Now proceed with the user ID we got from the database
	isDoctor, err := h.isUserDoctor(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to check if user is a doctor", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !isDoctor {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Doctor profile not found"})
	}

	// Get basic user info and doctor-specific data in one query
	var profile DoctorProfile
	var specializationJSON []byte

	err = h.pgPool.QueryRow(c.Context(),
		`WITH doctor_data AS (
            SELECT 
                COALESCE(imr_number, '') as imr_number,
                age,
                specialization,
                is_active,
                COALESCE(qualification, '') as qualification,
                COALESCE(slot_duration, 30) as slot_duration
            FROM doctors
            WHERE doctor_id = $1
        )

        SELECT 
            u.user_id,
            u.auth_id,
            COALESCE(u.username, '') as username,
            COALESCE(u.profile_pic, '') as profile_pic,
            COALESCE(u.name, '') as name,
            COALESCE(CAST(u.mobile AS TEXT), '') as mobile,
            COALESCE(u.email, $2) as email,
            COALESCE(u.blood_group, '') as blood_group,
            COALESCE(u.location, '') as location,
            COALESCE(u.address, '') as address,
            u.hospital_id,
            d.imr_number,
            d.age,
            d.specialization,
            d.is_active,
            d.qualification,
            d.slot_duration
        FROM users u
        JOIN doctor_data d ON true
        WHERE u.auth_id = $3`,
		userID, workosUser.Email, authID).Scan(
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
	)

	if err != nil {
		h.logger.Error("failed to fetch doctor profile", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch doctor profile"})
	}

	// Parse the JSONB specialization field
	if len(specializationJSON) > 0 {
		if err := json.Unmarshal(specializationJSON, &profile.Specialization); err != nil {
			h.logger.Error("failed to parse specialization JSON", zap.Error(err))
			// Continue without specialization rather than failing the whole request
			profile.Specialization = Specialization{Primary: "Unknown"}
		}
	} else {
		// Set default value if JSONB is null
		profile.Specialization = Specialization{Primary: ""}
	}

	return c.JSON(profile)
}

// GetDoctorSchedule retrieves the doctor's schedule
func (h *DoctorHandler) GetDoctorSchedule(c *fiber.Ctx) error {
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

	// Join with the doctors table to get the doctor's name
	rows, err := h.pgPool.Query(c.Context(),
		`SELECT ds.doctor_id, ds.hospital_id, d.name AS doctor_name, 
         ds.weekday, ds.starttime, ds.endtime, ds.isactive
         FROM doctorshifts ds
         JOIN doctors d ON ds.doctor_id = d.doctor_id
         WHERE ds.doctor_id = $1`, userID)
	if err != nil {
		h.logger.Error("failed to fetch doctor schedule", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch doctor schedule"})
	}
	defer rows.Close()

	var schedules []DoctorSchedule
	for rows.Next() {
		var schedule DoctorSchedule
		var startTime, endTime time.Time
		if err := rows.Scan(
			&schedule.DoctorID,
			&schedule.HospitalID,
			&schedule.DoctorName, // Add this new field
			&schedule.Weekday,
			&startTime,
			&endTime,
			&schedule.IsActive); err != nil {
			h.logger.Error("failed to scan doctor schedule", zap.Error(err))
			continue
		}

		schedule.StartTime = startTime.Format("15:04")
		schedule.EndTime = endTime.Format("15:04")
		schedules = append(schedules, schedule)
	}

	if err := rows.Err(); err != nil {
		h.logger.Error("error during schedule rows scan", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process doctor schedule"})
	}

	return c.JSON(schedules)
}

// GetDoctorFees retrieves the doctor's fees structure
func (h *DoctorHandler) GetDoctorFees(c *fiber.Ctx) error {
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

	// Use JOIN to get doctor name from the doctors table
	rows, err := h.pgPool.Query(c.Context(),
		`SELECT df.doctor_id, df.hospital_id, d.name AS doctor_name, 
         df.recurring_fees, df.default_fees, df.emergency_fees, df.created_at
         FROM doctor_fees df
         JOIN doctors d ON df.doctor_id = d.doctor_id
         WHERE df.doctor_id = $1`, userID)
	if err != nil {
		h.logger.Error("failed to fetch doctor fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch doctor fees"})
	}
	defer rows.Close()

	var feesStructures []DoctorFees
	for rows.Next() {
		var fees DoctorFees
		var createdAt time.Time
		if err := rows.Scan(&fees.DoctorID, &fees.HospitalID, &fees.DoctorName, &fees.RecurringFees,
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

	return c.JSON(feesStructures)
}

// UpdateDoctorProfile updates the doctor's profile information
func (h *DoctorHandler) UpdateDoctorProfile(c *fiber.Ctx) error {
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	var updateData DoctorProfile
	if err := c.BodyParser(&updateData); err != nil {
		h.logger.Error("failed to parse update data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	if err := h.validateDoctorProfileUpdate(&updateData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	defer tx.Rollback(c.Context())

	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	isDoctor, err := h.isUserDoctor(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to check if user is a doctor", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !isDoctor {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Doctor profile not found"})
	}

	// Convert specialization struct to JSON
	specializationJSON, err := json.Marshal(updateData.Specialization)
	if err != nil {
		h.logger.Error("failed to marshal specialization to JSON", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process specialization data"})
	}

	// Update in a single transaction
	_, err = tx.Exec(c.Context(),
		`UPDATE users SET username = $1, name = $2, mobile = $3, blood_group = $4, location = $5, address = $6
		 WHERE auth_id = $7`,
		updateData.Username, updateData.Name, updateData.Mobile, updateData.BloodGroup,
		updateData.Location, updateData.Address, authID)
	if err != nil {
		h.logger.Error("failed to update user profile", zap.Error(err), zap.String("auth_id", authID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update profile"})
	}

	_, err = tx.Exec(c.Context(),
		`UPDATE doctors SET imr_number = $1, age = $2, specialization = $3, is_active = $4, qualification = $5, slot_duration = $6
		 WHERE doctor_id = $7`,
		updateData.IMRNumber, updateData.Age, specializationJSON, updateData.IsActive,
		updateData.Qualification, updateData.SlotDuration, userID)
	if err != nil {
		h.logger.Error("failed to update doctor profile", zap.Error(err), zap.String("user_id", userID.String()))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update doctor profile"})
	}

	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	return c.JSON(fiber.Map{"message": "Doctor profile updated successfully"})
}

// CreateDoctorSchedule adds a new doctor's schedule
func (h *DoctorHandler) CreateDoctorSchedule(c *fiber.Ctx) error {
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	var scheduleData DoctorSchedule
	if err := c.BodyParser(&scheduleData); err != nil {
		h.logger.Error("failed to parse schedule data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	if err := h.validateScheduleData(&scheduleData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	hospitalID, err := uuid.Parse(scheduleData.HospitalID)
	if err != nil {
		h.logger.Error("invalid hospital ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid hospital ID format"})
	}

	hospitalExists, err := h.checkHospitalExists(c.Context(), hospitalID)
	if err != nil {
		h.logger.Error("failed to check hospital existence", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !hospitalExists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Hospital not found"})
	}

	startTime, err := time.Parse("15:04", scheduleData.StartTime)
	if err != nil {
		h.logger.Error("failed to parse start time", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid start time format. Use HH:MM (24-hour format)"})
	}

	endTime, err := time.Parse("15:04", scheduleData.EndTime)
	if err != nil {
		h.logger.Error("failed to parse end time", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid end time format. Use HH:MM (24-hour format)"})
	}

	// Check if schedule already exists
	var exists bool
	err = h.pgPool.QueryRow(c.Context(),
		`SELECT EXISTS(SELECT 1 FROM doctorshifts WHERE doctor_id = $1 AND weekday = $2 AND hospital_id = $3)`,
		userID, scheduleData.Weekday, scheduleData.HospitalID).Scan(&exists)
	if err != nil {
		h.logger.Error("failed to check if schedule exists", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if exists {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Schedule already exists for this day and hospital"})
	}

	_, err = h.pgPool.Exec(c.Context(),
		`INSERT INTO doctorshifts (doctor_id, hospital_id, weekday, starttime, endtime, isactive) 
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, scheduleData.HospitalID, scheduleData.Weekday, startTime, endTime, scheduleData.IsActive)
	if err != nil {
		h.logger.Error("failed to create doctor schedule", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create schedule"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "Schedule created successfully"})
}

// UpdateDoctorSchedule adds or updates the doctor's schedule
func (h *DoctorHandler) UpdateDoctorSchedule(c *fiber.Ctx) error {
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	var scheduleData DoctorSchedule
	if err := c.BodyParser(&scheduleData); err != nil {
		h.logger.Error("failed to parse schedule data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	if err := h.validateScheduleData(&scheduleData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	hospitalID, err := uuid.Parse(scheduleData.HospitalID)
	if err != nil {
		h.logger.Error("invalid hospital ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid hospital ID format"})
	}

	hospitalExists, err := h.checkHospitalExists(c.Context(), hospitalID)
	if err != nil {
		h.logger.Error("failed to check hospital existence", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !hospitalExists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Hospital not found"})
	}

	startTime, err := time.Parse("15:04", scheduleData.StartTime)
	if err != nil {
		h.logger.Error("failed to parse start time", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid start time format. Use HH:MM (24-hour format)"})
	}

	endTime, err := time.Parse("15:04", scheduleData.EndTime)
	if err != nil {
		h.logger.Error("failed to parse end time", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid end time format. Use HH:MM (24-hour format)"})
	}

	_, err = h.pgPool.Exec(c.Context(),
		`INSERT INTO doctorshifts (doctor_id, hospital_id, weekday, starttime, endtime, isactive) 
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (doctor_id, weekday, hospital_id) 
		 DO UPDATE SET starttime = $4, endtime = $5, isactive = $6`,
		userID, scheduleData.HospitalID, scheduleData.Weekday, startTime, endTime, scheduleData.IsActive)
	if err != nil {
		h.logger.Error("failed to update doctor schedule", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update schedule"})
	}

	return c.JSON(fiber.Map{"message": "Schedule updated successfully"})
}

// CreateDoctorFees adds a new doctor's fees structure
func (h *DoctorHandler) CreateDoctorFees(c *fiber.Ctx) error {
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	var feesData DoctorFees
	if err := c.BodyParser(&feesData); err != nil {
		h.logger.Error("failed to parse fees data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	if err := h.validateFeesData(&feesData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var userID uuid.UUID
	var userName string
	err = h.pgPool.QueryRow(c.Context(),
		"SELECT u.user_id, d.name FROM users u JOIN doctors d ON u.user_id = d.doctor_id WHERE u.auth_id = $1",
		authID).Scan(&userID, &userName)
	if err != nil {
		h.logger.Error("failed to get user ID and name", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	hospitalID := feesData.HospitalID

	hospitalExists, err := h.checkHospitalExists(c.Context(), hospitalID)
	if err != nil {
		h.logger.Error("failed to check hospital existence", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !hospitalExists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Hospital not found"})
	}

	// Check if fees already exist
	var exists bool
	err = h.pgPool.QueryRow(c.Context(),
		`SELECT EXISTS(SELECT 1 FROM doctor_fees WHERE doctor_id = $1 AND hospital_id = $2)`,
		userID, hospitalID).Scan(&exists)
	if err != nil {
		h.logger.Error("failed to check if fees exist", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if exists {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Fees already exist for this hospital"})
	}

	_, err = h.pgPool.Exec(c.Context(),
		`INSERT INTO doctor_fees (doctor_id, hospital_id, recurring_fees, default_fees, emergency_fees, created_at) 
		 VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`,
		userID, hospitalID, feesData.RecurringFees, feesData.DefaultFees, feesData.EmergencyFees)
	if err != nil {
		h.logger.Error("failed to create doctor fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create fees"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "Fees created successfully"})
}

// UpdateDoctorFees adds or updates the doctor's fees structure
func (h *DoctorHandler) UpdateDoctorFees(c *fiber.Ctx) error {
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	var feesData DoctorFees
	if err := c.BodyParser(&feesData); err != nil {
		h.logger.Error("failed to parse fees data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	if err := h.validateFeesData(&feesData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var userID uuid.UUID
	var userName string
	err = h.pgPool.QueryRow(c.Context(), "SELECT user_id, name FROM users WHERE auth_id = $1", authID).Scan(&userID, &userName)
	if err != nil {
		h.logger.Error("failed to get user ID and name", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	hospitalExists, err := h.checkHospitalExists(c.Context(), feesData.HospitalID)
	if err != nil {
		h.logger.Error("failed to check hospital existence", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !hospitalExists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Hospital not found"})
	}

	_, err = h.pgPool.Exec(c.Context(),
		`INSERT INTO doctor_fees (doctor_id, hospital_id, doctor_name, recurring_fees, default_fees, emergency_fees, created_at) 
		 VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
		 ON CONFLICT (doctor_id, hospital_id) 
		 DO UPDATE SET doctor_name = $3, recurring_fees = $4, default_fees = $5, emergency_fees = $6, created_at = CURRENT_TIMESTAMP`,
		userID, feesData.HospitalID, userName, feesData.RecurringFees, feesData.DefaultFees, feesData.EmergencyFees)
	if err != nil {
		h.logger.Error("failed to update doctor fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update fees"})
	}

	return c.JSON(fiber.Map{"message": "Fees updated successfully"})
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

// validateScheduleData validates the doctor schedule data
func (h *DoctorHandler) validateScheduleData(schedule *DoctorSchedule) error {
	validWeekdays := map[string]bool{
		"Monday": true, "Tuesday": true, "Wednesday": true,
		"Thursday": true, "Friday": true, "Saturday": true, "Sunday": true,
	}

	if !validWeekdays[schedule.Weekday] {
		h.logger.Error("invalid weekday", zap.String("weekday", schedule.Weekday))
		return errors.New("invalid weekday. Must be one of: Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday")
	}

	_, err := time.Parse("15:04", schedule.StartTime)
	return err
}

// validateFeesData validates the doctor fees data
func (h *DoctorHandler) validateFeesData(fees *DoctorFees) error {
	if fees.RecurringFees < 0 || fees.DefaultFees < 0 || fees.EmergencyFees < 0 {
		return errors.New("fees cannot be negative")
	}
	return nil
}

// DeleteDoctorSchedule deletes a doctor's schedule entry
func (h *DoctorHandler) DeleteDoctorSchedule(c *fiber.Ctx) error {
	scheduleId := c.Params("id")
	if scheduleId == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Schedule ID is required"})
	}

	// Get the authorized user
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

	// Delete the schedule, ensuring it belongs to the current doctor
	result, err := h.pgPool.Exec(c.Context(),
		`DELETE FROM doctorshifts WHERE id = $1 AND doctor_id = $2`, scheduleId, userID)
	if err != nil {
		h.logger.Error("failed to delete doctor schedule", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete schedule"})
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Schedule not found or you don't have permission to delete it"})
	}

	return c.JSON(fiber.Map{"message": "Schedule deleted successfully"})
}

// DeleteDoctorFees deletes a doctor's fees entry
func (h *DoctorHandler) DeleteDoctorFees(c *fiber.Ctx) error {
	feesId := c.Params("id")
	if feesId == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Fees ID is required"})
	}
	// Get the authorized user
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

	// Delete the fees entry, ensuring it belongs to the current doctor
	result, err := h.pgPool.Exec(c.Context(),
		`DELETE FROM doctor_fees WHERE id = $1 AND doctor_id = $2`, feesId, userID)
	if err != nil {
		h.logger.Error("failed to delete doctor fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete fees"})
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Fees not found or you don't have permission to delete it"})
	}

	return c.JSON(fiber.Map{"message": "Fees deleted successfully"})
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
