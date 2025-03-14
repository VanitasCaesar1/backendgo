package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/organizations"
	"go.uber.org/zap"
)

type HospitalHandler struct {
	config      *config.Config
	redisClient *redis.Client
	logger      *zap.Logger
	pgPool      *pgxpool.Pool
}

type HospitalFee struct {
	ID        uuid.UUID `json:"id,omitempty"`
	FeeType   string    `json:"fee_type"`
	Amount    float64   `json:"amount"`
	CreatedAt string    `json:"created_at,omitempty"`
}

type Hospital struct {
	AdminID       uuid.UUID       `json:"admin_id"`
	OrgID         string          `json:"org_id"`
	Name          string          `json:"name"`
	Email         string          `json:"email"`
	Number        int64           `json:"number"`
	Address       string          `json:"address"`
	LicenseNumber string          `json:"license_number,omitempty"`
	StartTime     time.Time       `json:"start_time"`
	EndTime       time.Time       `json:"end_time"`
	Location      string          `json:"location"`
	HospitalPics  json.RawMessage `json:"hospital_pics,omitempty"`
	Speciality    string          `json:"speciality,omitempty"`
	CreatedAt     string          `json:"created_at,omitempty"`
	Fees          []HospitalFee   `json:"fees,omitempty"`
}

func NewHospitalHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, pgPool *pgxpool.Pool) (*HospitalHandler, error) {
	organizations.SetAPIKey(cfg.WorkOSApiKey)
	return &HospitalHandler{
		config:      cfg,
		redisClient: rds,
		logger:      logger,
		pgPool:      pgPool,
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

func (h *HospitalHandler) isUserAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	var isAdmin bool
	err := h.pgPool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM admins WHERE user_id = $1)", userID).Scan(&isAdmin)
	return isAdmin, err
}

// CreateHospital creates a new hospital with a WorkOS organization
func (h *HospitalHandler) CreateHospital(c *fiber.Ctx) error {
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	var hospitalData Hospital
	if err := c.BodyParser(&hospitalData); err != nil {
		h.logger.Error("failed to parse hospital data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request data"})
	}

	if err := h.validateHospitalData(&hospitalData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	isAdmin, err := h.isUserAdmin(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to check if user is admin", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !isAdmin {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only administrators can create hospitals"})
	}

	// Create a WorkOS organization for the hospital
	org, err := organizations.CreateOrganization(
		c.Context(),
		organizations.CreateOrganizationOpts{
			Name: hospitalData.Name,
		},
	)
	if err != nil {
		h.logger.Error("failed to create WorkOS organization", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create organization for hospital",
		})
	}

	// Start a transaction
	tx, err := h.pgPool.Begin(c.Context())
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	defer tx.Rollback(c.Context())

	// Insert hospital data
	_, err = tx.Exec(c.Context(),
		`INSERT INTO hospitals (
			admin_id, org_id, name, email, number, address, license_number, 
			start_time, end_time, location, hospital_pics, speciality, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, CURRENT_TIMESTAMP)`,
		userID, org.ID, hospitalData.Name, hospitalData.Email, hospitalData.Number, hospitalData.Address,
		hospitalData.LicenseNumber, hospitalData.StartTime, hospitalData.EndTime, hospitalData.Location,
		hospitalData.HospitalPics, hospitalData.Speciality,
	)
	if err != nil {
		h.logger.Error("failed to insert hospital data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create hospital"})
	}

	// Insert fee data if provided
	if hospitalData.Fees != nil && len(hospitalData.Fees) > 0 {
		for _, fee := range hospitalData.Fees {
			_, err = tx.Exec(c.Context(),
				`INSERT INTO hospital_fees (
					fee_type, amount, hospital_id, created_at
				) VALUES ($1, $2, $3, CURRENT_TIMESTAMP)`,
				fee.FeeType, fee.Amount, userID,
			)
			if err != nil {
				h.logger.Error("failed to insert fee data", zap.Error(err))
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add hospital fees"})
			}
		}
	}

	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Return the created hospital with its ID
	hospitalData.AdminID = userID
	hospitalData.OrgID = org.ID
	hospitalData.CreatedAt = time.Now().Format(time.RFC3339)

	return c.Status(fiber.StatusCreated).JSON(hospitalData)
}

// GetHospital retrieves a specific hospital by ID
func (h *HospitalHandler) GetHospital(c *fiber.Ctx) error {
	hospitalID := c.Params("id")
	if hospitalID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Hospital ID is required"})
	}

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
	parsedHospitalID, err := uuid.Parse(hospitalID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid hospital ID format"})
	}

	var hospital Hospital
	var createdAt time.Time

	err = h.pgPool.QueryRow(c.Context(),
		`SELECT 
			admin_id, org_id, name, email, number, address, license_number, 
			start_time, end_time, location, hospital_pics, speciality, created_at
		FROM hospitals WHERE admin_id = $1`,
		parsedHospitalID).Scan(
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

	// Only allow the admin to update their own hospital or if user is system admin
	isSystemAdmin, err := h.isUserAdmin(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to check admin status", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !isSystemAdmin && userID != parsedHospitalID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "You don't have permission to update this hospital"})
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
	err = h.pgPool.QueryRow(c.Context(), "SELECT org_id FROM hospitals WHERE admin_id = $1", parsedHospitalID).Scan(&orgID)
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

	// Update the hospital in the database
	_, err = tx.Exec(c.Context(),
		`UPDATE hospitals SET 
			name = $1, email = $2, number = $3, address = $4, license_number = $5,
			start_time = $6, end_time = $7, location = $8, hospital_pics = $9, speciality = $10
		WHERE admin_id = $11`,
		updateData.Name, updateData.Email, updateData.Number, updateData.Address, updateData.LicenseNumber,
		updateData.StartTime, updateData.EndTime, updateData.Location, updateData.HospitalPics, updateData.Speciality,
		parsedHospitalID,
	)
	if err != nil {
		h.logger.Error("failed to update hospital data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update hospital"})
	}

	// Update fees if provided
	if updateData.Fees != nil && len(updateData.Fees) > 0 {
		// Delete existing fees
		_, err = tx.Exec(c.Context(), "DELETE FROM hospital_fees WHERE hospital_id = $1", parsedHospitalID)
		if err != nil {
			h.logger.Error("failed to delete existing fees", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update hospital fees"})
		}

		// Insert new fees
		for _, fee := range updateData.Fees {
			_, err = tx.Exec(c.Context(),
				`INSERT INTO hospital_fees (fee_type, amount, hospital_id, created_at)
				VALUES ($1, $2, $3, CURRENT_TIMESTAMP)`,
				fee.FeeType, fee.Amount, parsedHospitalID,
			)
			if err != nil {
				h.logger.Error("failed to insert fee data", zap.Error(err))
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update hospital fees"})
			}
		}
	}

	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
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

	// Check if user is a system admin
	isAdmin, err := h.isUserAdmin(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to check admin status", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !isAdmin && userID != parsedHospitalID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only system administrators or the hospital admin can delete this hospital"})
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

	// Validate time range
	if hospital.StartTime.IsZero() || hospital.EndTime.IsZero() {
		return errors.New("Start time and end time are required")
	}

	if hospital.EndTime.Before(hospital.StartTime) {
		return errors.New("End time must be after start time")
	}

	return nil
}
