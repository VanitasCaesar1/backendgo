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
	"github.com/jackc/pgx/v5"
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

type HospitalAddress struct {
	Street     string `json:"street"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

type Hospital struct {
	ID              uuid.UUID       `json:"id,omitempty"`
	OrgID           string          `json:"org_id"`
	Name            string          `json:"name"`
	Email           string          `json:"email"`
	Phone           string          `json:"phone,omitempty"`
	Address         HospitalAddress `json:"address"`
	Website         string          `json:"website,omitempty"`
	Description     string          `json:"description,omitempty"`
	Logo            string          `json:"logo,omitempty"`
	EstablishedYear int             `json:"established_year,omitempty"`
	IsActive        bool            `json:"is_active"`
	AdminUserID     uuid.UUID       `json:"admin_user_id,omitempty"`
	CreatedAt       string          `json:"created_at,omitempty"`
	UpdatedAt       string          `json:"updated_at,omitempty"`
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

func (h *HospitalHandler) isHospitalAdmin(ctx context.Context, userID uuid.UUID, hospitalID uuid.UUID) (bool, error) {
	var isAdmin bool
	err := h.pgPool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM hospital_admins WHERE user_id = $1 AND hospital_id = $2)",
		userID, hospitalID).Scan(&isAdmin)
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
	domain := ""
	if hospitalData.Website != "" {
		// Extract domain from website
		re := regexp.MustCompile(`^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+)`)
		matches := re.FindStringSubmatch(hospitalData.Website)
		if len(matches) > 1 {
			domain = matches[1]
		}
	}

	var domainData []organizations.OrganizationDomainData
	if domain != "" {
		domainData = []organizations.OrganizationDomainData{
			{
				Domain: domain,
			},
		}
	}

	org, err := organizations.CreateOrganization(
		c.Context(),
		organizations.CreateOrganizationOpts{
			Name:       hospitalData.Name,
			DomainData: domainData,
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

	// Create new UUID for the hospital
	hospitalID := uuid.New()

	// Convert address to JSON
	addressJSON, err := json.Marshal(hospitalData.Address)
	if err != nil {
		h.logger.Error("failed to marshal address to JSON", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process address data"})
	}

	// Insert hospital data
	_, err = tx.Exec(c.Context(),
		`INSERT INTO hospitals (
			id, org_id, name, email, phone, address, website, 
			description, logo, established_year, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		hospitalID, org.ID, hospitalData.Name, hospitalData.Email, hospitalData.Phone, addressJSON,
		hospitalData.Website, hospitalData.Description, hospitalData.Logo, hospitalData.EstablishedYear,
		hospitalData.IsActive,
	)
	if err != nil {
		h.logger.Error("failed to insert hospital data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create hospital"})
	}

	// Insert hospital admin relationship
	_, err = tx.Exec(c.Context(),
		`INSERT INTO hospital_admins (hospital_id, user_id, created_at)
		 VALUES ($1, $2, CURRENT_TIMESTAMP)`,
		hospitalID, userID,
	)
	if err != nil {
		h.logger.Error("failed to insert hospital admin relationship", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to assign admin to hospital"})
	}

	if err := tx.Commit(c.Context()); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Return the created hospital with its ID
	hospitalData.ID = hospitalID
	hospitalData.OrgID = org.ID
	hospitalData.AdminUserID = userID

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
	var addressJSON []byte
	var createdAt, updatedAt time.Time

	err = h.pgPool.QueryRow(c.Context(),
		`SELECT id, org_id, name, email, phone, address, website, 
			description, logo, established_year, is_active, created_at, updated_at
		 FROM hospitals WHERE id = $1`,
		parsedHospitalID).Scan(
		&hospital.ID,
		&hospital.OrgID,
		&hospital.Name,
		&hospital.Email,
		&hospital.Phone,
		&addressJSON,
		&hospital.Website,
		&hospital.Description,
		&hospital.Logo,
		&hospital.EstablishedYear,
		&hospital.IsActive,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		h.logger.Error("failed to fetch hospital", zap.Error(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Hospital not found"})
	}

	// Parse the JSONB address field
	if err := json.Unmarshal(addressJSON, &hospital.Address); err != nil {
		h.logger.Error("failed to parse address JSON", zap.Error(err))
		hospital.Address = HospitalAddress{}
	}

	hospital.CreatedAt = createdAt.Format(time.RFC3339)
	hospital.UpdatedAt = updatedAt.Format(time.RFC3339)

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

	// Check if user is a hospital admin
	isAdmin, err := h.isHospitalAdmin(c.Context(), userID, parsedHospitalID)
	if err != nil {
		h.logger.Error("failed to check hospital admin status", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !isAdmin {
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

	// Convert address to JSON
	addressJSON, err := json.Marshal(updateData.Address)
	if err != nil {
		h.logger.Error("failed to marshal address to JSON", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process address data"})
	}

	// Get the current WorkOS organization ID
	var orgID string
	err = h.pgPool.QueryRow(c.Context(), "SELECT org_id FROM hospitals WHERE id = $1", parsedHospitalID).Scan(&orgID)
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

	// Update the hospital in the database
	// Update the hospital in the database
	_, err = h.pgPool.Exec(c.Context(),
		`UPDATE hospitals SET 
	name = $1, email = $2, phone = $3, address = $4, website = $5,
	description = $6, logo = $7, established_year = $8, is_active = $9, updated_at = CURRENT_TIMESTAMP
WHERE id = $10`,
		updateData.Name, updateData.Email, updateData.Phone, addressJSON, updateData.Website,
		updateData.Description, updateData.Logo, updateData.EstablishedYear, updateData.IsActive,
		parsedHospitalID,
	)
	if err != nil {
		h.logger.Error("failed to update hospital data", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update hospital"})
	}

	// Fetch the updated hospital data to return
	var hospital Hospital
	var createdAt, updatedAt time.Time

	err = h.pgPool.QueryRow(c.Context(),
		`SELECT id, org_id, name, email, phone, address, website, 
	description, logo, established_year, is_active, created_at, updated_at
 FROM hospitals WHERE id = $1`,
		parsedHospitalID).Scan(
		&hospital.ID,
		&hospital.OrgID,
		&hospital.Name,
		&hospital.Email,
		&hospital.Phone,
		&addressJSON,
		&hospital.Website,
		&hospital.Description,
		&hospital.Logo,
		&hospital.EstablishedYear,
		&hospital.IsActive,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		h.logger.Error("failed to fetch updated hospital", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Hospital updated but failed to retrieve data"})
	}

	// Parse the JSONB address field
	if err := json.Unmarshal(addressJSON, &hospital.Address); err != nil {
		h.logger.Error("failed to parse address JSON", zap.Error(err))
		hospital.Address = HospitalAddress{}
	}

	hospital.CreatedAt = createdAt.Format(time.RFC3339)
	hospital.UpdatedAt = updatedAt.Format(time.RFC3339)

	return c.JSON(hospital)
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

	if !isAdmin {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only system administrators can delete hospitals"})
	}

	// Get the WorkOS organization ID
	var orgID string
	err = h.pgPool.QueryRow(c.Context(), "SELECT org_id FROM hospitals WHERE id = $1", parsedHospitalID).Scan(&orgID)
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

	// Delete hospital admin relationships
	_, err = tx.Exec(c.Context(), "DELETE FROM hospital_admins WHERE hospital_id = $1", parsedHospitalID)
	if err != nil {
		h.logger.Error("failed to delete hospital admin relationships", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Delete hospital
	_, err = tx.Exec(c.Context(), "DELETE FROM hospitals WHERE id = $1", parsedHospitalID)
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

	// Check if user is a system admin
	isAdmin, err := h.isUserAdmin(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to check admin status", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	var rows pgx.Rows
	if isAdmin {
		// System admins can see all hospitals
		rows, err = h.pgPool.Query(c.Context(),
			`SELECT id, org_id, name, email, phone, address, website, 
			description, logo, established_year, is_active, created_at, updated_at
		 FROM hospitals ORDER BY name`)
	} else {
		// Regular users can only see hospitals they're admins of
		rows, err = h.pgPool.Query(c.Context(),
			`SELECT h.id, h.org_id, h.name, h.email, h.phone, h.address, h.website, 
			h.description, h.logo, h.established_year, h.is_active, h.created_at, h.updated_at
		 FROM hospitals h
		 JOIN hospital_admins ha ON h.id = ha.hospital_id
		 WHERE ha.user_id = $1
		 ORDER BY h.name`, userID)
	}

	if err != nil {
		h.logger.Error("failed to query hospitals", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	defer rows.Close()

	hospitals := []Hospital{}
	for rows.Next() {
		var hospital Hospital
		var addressJSON []byte
		var createdAt, updatedAt time.Time

		err := rows.Scan(
			&hospital.ID,
			&hospital.OrgID,
			&hospital.Name,
			&hospital.Email,
			&hospital.Phone,
			&addressJSON,
			&hospital.Website,
			&hospital.Description,
			&hospital.Logo,
			&hospital.EstablishedYear,
			&hospital.IsActive,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan hospital row", zap.Error(err))
			continue
		}

		// Parse the JSONB address field
		if err := json.Unmarshal(addressJSON, &hospital.Address); err != nil {
			h.logger.Error("failed to parse address JSON", zap.Error(err))
			hospital.Address = HospitalAddress{}
		}

		hospital.CreatedAt = createdAt.Format(time.RFC3339)
		hospital.UpdatedAt = updatedAt.Format(time.RFC3339)
		hospitals = append(hospitals, hospital)
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

	if hospital.Address.Street == "" || hospital.Address.City == "" ||
		hospital.Address.State == "" || hospital.Address.PostalCode == "" ||
		hospital.Address.Country == "" {
		return errors.New("complete address information is required")
	}

	return nil
}
