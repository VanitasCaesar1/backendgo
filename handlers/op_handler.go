package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.uber.org/zap"
)

type AppointmentHandler struct {
	config      *config.Config
	redisClient *redis.Client
	logger      *zap.Logger
	pgPool      *pgxpool.Pool
	mongoClient *mongo.Client
}

type Hospitals struct {
	Name          string    `json:"name"`
	Address       string    `json:"address"`
	Number        int64     `json:"number"`
	LicenseNumber string    `json:"license_number"`
	Email         string    `json:"email"`
	StartTime     string    `json:"start_time"`
	EndTime       string    `json:"end_time"`
	Location      string    `json:"location"`
	AdminID       uuid.UUID `json:"admin_id"`
	Speciality    string    `json:"speciality"`
	OrgID         string    `json:"org_id"`
	HospitalID    uuid.UUID `json:"hospital_id"`
}

type Appointment struct {
	PatientID         string    `json:"patient_id" bson:"patient_id"`
	DoctorID          string    `json:"doctor_id" bson:"doctor_id"`
	HospitalID        string    `json:"hospital_id" bson:"hospital_id"`
	PatientName       string    `json:"patient_name" bson:"patient_name"`
	DoctorName        string    `json:"doctor_name" bson:"doctor_name"`
	AppointmentStatus string    `json:"appointment_status" bson:"appointment_status"`
	PaymentMethod     string    `json:"payment_method" bson:"payment_method"`
	FeeType           string    `json:"fee_type" bson:"fee_type"`
	AppointmentFee    int       `json:"appointment_fee" bson:"appointment_fee"` // Changed from string to int
	AppointmentDate   time.Time `json:"appointment_date,omitempty" bson:"appointment_date,omitempty"`
	CreatedAt         time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt         time.Time `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
}

type AppointmentResponse struct {
	PatientID         string `json:"patient_id"`
	DoctorID          string `json:"doctor_id"`
	HospitalID        string `json:"hospital_id"`
	PatientName       string `json:"patient_name"`
	DoctorName        string `json:"doctor_name"`
	AppointmentStatus string `json:"appointment_status"`
	PaymentMethod     string `json:"payment_method"`
	FeeType           string `json:"fee_type"`
	AppointmentFee    int    `json:"appointment_fee"` // Changed from float64 to int
	AppointmentDate   string `json:"appointment_date,omitempty"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at,omitempty"`
}

type AppointmentFilters struct {
	Status    string `query:"status"`
	StartDate string `query:"start_date"`
	EndDate   string `query:"end_date"`
	DoctorID  string `query:"doctor_id"`
	Limit     int64  `query:"limit"`
	Offset    int64  `query:"offset"`
}

func NewAppointmentHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, pgPool *pgxpool.Pool, mongoClient *mongo.Client) (*AppointmentHandler, error) {
	usermanagement.SetAPIKey(cfg.WorkOSApiKey)
	return &AppointmentHandler{
		config:      cfg,
		redisClient: rds,
		logger:      logger,
		pgPool:      pgPool,
		mongoClient: mongoClient,
	}, nil
}

// Helper functions
func (h *AppointmentHandler) getUserID(ctx context.Context, authID string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := h.pgPool.QueryRow(ctx, "SELECT user_id FROM users WHERE auth_id = $1", authID).Scan(&userID)
	return userID, err
}

func (h *AppointmentHandler) getHospitalIDFromOrgID(ctx context.Context, orgID string) (uuid.UUID, error) {
	var hospitalID uuid.UUID
	err := h.pgPool.QueryRow(ctx, "SELECT hospital_id FROM hospitals WHERE org_id = $1", orgID).Scan(&hospitalID)
	return hospitalID, err
}

func (h *AppointmentHandler) getAuthID(c *fiber.Ctx) (string, error) {
	authID, ok := c.Locals("authID").(string)
	if !ok {
		return "", fmt.Errorf("auth ID not found")
	}
	return authID, nil
}

func (h *AppointmentHandler) getUserRole(ctx context.Context, userID uuid.UUID) (string, error) {
	var role string
	err := h.pgPool.QueryRow(ctx, "SELECT role FROM users WHERE user_id = $1", userID).Scan(&role)
	return role, err
}

// GetAppointmentsByOrgID retrieves appointments based on org_id
func (h *AppointmentHandler) GetAppointmentsByOrgID(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get org ID from params
	orgID := c.Params("orgID")
	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required"})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err), zap.String("authID", authID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve user information"})
	}

	// Check user role to ensure they have permission
	role, err := h.getUserRole(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get user role", zap.Error(err), zap.String("userID", userID.String()))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve user role"})
	}

	// Only admin or hospital_admin roles should be able to view appointments by org ID
	if role != "admin" && role != "hospital_admin" {
		h.logger.Error("unauthorized access attempt", zap.String("userID", userID.String()), zap.String("role", role))
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Not authorized to view organization appointments"})
	}

	// Get hospital ID from org ID
	hospitalID, err := h.getHospitalIDFromOrgID(c.Context(), orgID)
	if err != nil {
		h.logger.Error("failed to get hospital ID from org ID", zap.Error(err), zap.String("orgID", orgID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Hospital not found for this organization"})
	}

	// Parse query filters
	var filters AppointmentFilters
	if err := c.QueryParser(&filters); err != nil {
		h.logger.Error("failed to parse query parameters", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid query parameters"})
	}

	// Set defaults for pagination
	if filters.Limit <= 0 {
		filters.Limit = 20 // Default limit
	}
	if filters.Limit > 100 {
		filters.Limit = 100 // Maximum limit
	}

	// Build MongoDB query
	query := bson.M{"hospital_id": hospitalID.String()}

	// Add status filter if provided
	if filters.Status != "" {
		query["appointment_status"] = filters.Status
	}

	// Add date range filters if provided
	if filters.StartDate != "" || filters.EndDate != "" {
		dateFilter := bson.M{}

		if filters.StartDate != "" {
			startDate, err := time.Parse("2006-01-02", filters.StartDate)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid start date format. Use YYYY-MM-DD"})
			}
			dateFilter["$gte"] = startDate
		}

		if filters.EndDate != "" {
			endDate, err := time.Parse("2006-01-02", filters.EndDate)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid end date format. Use YYYY-MM-DD"})
			}
			// Add one day to include the entire end date
			endDate = endDate.Add(24 * time.Hour)
			dateFilter["$lt"] = endDate
		}

		query["appointment_date"] = dateFilter
	}

	// Add doctor filter if provided
	if filters.DoctorID != "" {
		query["doctor_id"] = filters.DoctorID
	}

	// Configure find options
	findOptions := options.Find()
	findOptions.SetLimit(filters.Limit)
	findOptions.SetSkip(filters.Offset)
	findOptions.SetSort(bson.D{{Key: "appointment_date", Value: -1}}) // Sort by appointment date, newest first

	// Query MongoDB
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	cursor, err := appointmentsCollection.Find(c.Context(), query, findOptions)
	if err != nil {
		h.logger.Error("failed to query appointments", zap.Error(err), zap.String("hospitalID", hospitalID.String()))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch appointments"})
	}
	defer cursor.Close(c.Context())

	// Process appointments
	var appointments []AppointmentResponse
	for cursor.Next(c.Context()) {
		var appointment Appointment
		if err := cursor.Decode(&appointment); err != nil {
			h.logger.Error("failed to decode appointment", zap.Error(err))
			continue
		}

		// Convert to response format
		appointmentDateStr := ""
		if !appointment.AppointmentDate.IsZero() {
			appointmentDateStr = appointment.AppointmentDate.Format(time.RFC3339)
		}

		updatedAtStr := ""
		if !appointment.UpdatedAt.IsZero() {
			updatedAtStr = appointment.UpdatedAt.Format(time.RFC3339)
		}

		appointments = append(appointments, AppointmentResponse{
			PatientID:         appointment.PatientID,
			DoctorID:          appointment.DoctorID,
			HospitalID:        appointment.HospitalID,
			PatientName:       appointment.PatientName,
			DoctorName:        appointment.DoctorName,
			AppointmentStatus: appointment.AppointmentStatus,
			PaymentMethod:     appointment.PaymentMethod,
			FeeType:           appointment.FeeType,
			AppointmentFee:    appointment.AppointmentFee, // No conversion needed - already int
			AppointmentDate:   appointmentDateStr,
			CreatedAt:         appointment.CreatedAt.Format(time.RFC3339),
			UpdatedAt:         updatedAtStr,
		})
	}

	if err := cursor.Err(); err != nil {
		h.logger.Error("cursor error", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error processing appointments"})
	}

	// Get total count for pagination
	total, err := appointmentsCollection.CountDocuments(c.Context(), query)
	if err != nil {
		h.logger.Error("failed to count appointments", zap.Error(err))
		// Continue with the results but without total count
		total = 0
	}

	return c.JSON(fiber.Map{
		"appointments": appointments,
		"pagination": fiber.Map{
			"total":  total,
			"limit":  filters.Limit,
			"offset": filters.Offset,
		},
	})
}

// CreateAppointment creates a new appointment
func (h *AppointmentHandler) CreateAppointment(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Parse appointment data from request body
	var appointment Appointment
	if err := c.BodyParser(&appointment); err != nil {
		h.logger.Error("failed to parse appointment data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment data"})
	}

	// Validate required fields
	if appointment.PatientID == "" || appointment.DoctorID == "" || appointment.HospitalID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "PatientID, DoctorID, and HospitalID are required"})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Check user role
	_, err = h.getUserRole(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get user role", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Set creation timestamps
	appointment.CreatedAt = time.Now()
	appointment.UpdatedAt = time.Now()

	// Insert appointment into MongoDB
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	_, err = appointmentsCollection.InsertOne(c.Context(), appointment)
	if err != nil {
		h.logger.Error("failed to insert appointment", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create appointment"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":     "Appointment created successfully",
		"appointment": appointment,
	})
}

// GetAppointment retrieves a single appointment by ID
func (h *AppointmentHandler) GetAppointment(c *fiber.Ctx) error {
	// Get appointment ID from params
	appointmentID := c.Params("id")
	if appointmentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Appointment ID is required"})
	}

	// Query MongoDB for the appointment
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	var appointment Appointment

	objID, err := primitive.ObjectIDFromHex(appointmentID)
	if err != nil {
		h.logger.Error("invalid appointment ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment ID format"})
	}

	err = appointmentsCollection.FindOne(c.Context(), bson.M{"_id": objID}).Decode(&appointment)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Appointment not found"})
		}
		h.logger.Error("failed to fetch appointment", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch appointment"})
	}

	// Convert to response format
	appointmentDateStr := ""
	if !appointment.AppointmentDate.IsZero() {
		appointmentDateStr = appointment.AppointmentDate.Format(time.RFC3339)
	}

	updatedAtStr := ""
	if !appointment.UpdatedAt.IsZero() {
		updatedAtStr = appointment.UpdatedAt.Format(time.RFC3339)
	}

	response := AppointmentResponse{
		PatientID:         appointment.PatientID,
		DoctorID:          appointment.DoctorID,
		HospitalID:        appointment.HospitalID,
		PatientName:       appointment.PatientName,
		DoctorName:        appointment.DoctorName,
		AppointmentStatus: appointment.AppointmentStatus,
		PaymentMethod:     appointment.PaymentMethod,
		FeeType:           appointment.FeeType,
		AppointmentFee:    appointment.AppointmentFee,
		AppointmentDate:   appointmentDateStr,
		CreatedAt:         appointment.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         updatedAtStr,
	}

	return c.JSON(response)
}

// GetDoctorAppointments retrieves appointments for a specific doctor
func (h *AppointmentHandler) GetDoctorAppointments(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get doctor ID from params
	doctorID := c.Params("id")
	if doctorID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor ID is required"})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	fmt.Println(userID)
	// Parse query filters
	var filters AppointmentFilters
	if err := c.QueryParser(&filters); err != nil {
		h.logger.Error("failed to parse query parameters", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid query parameters"})
	}

	// Set defaults for pagination
	if filters.Limit <= 0 {
		filters.Limit = 20 // Default limit
	}
	if filters.Limit > 100 {
		filters.Limit = 100 // Maximum limit
	}

	// Build MongoDB query
	query := bson.M{"doctor_id": doctorID}

	// Add status filter if provided
	if filters.Status != "" {
		query["appointment_status"] = filters.Status
	}

	// Add date range filters if provided
	if filters.StartDate != "" || filters.EndDate != "" {
		dateFilter := bson.M{}

		if filters.StartDate != "" {
			startDate, err := time.Parse("2006-01-02", filters.StartDate)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid start date format. Use YYYY-MM-DD"})
			}
			dateFilter["$gte"] = startDate
		}

		if filters.EndDate != "" {
			endDate, err := time.Parse("2006-01-02", filters.EndDate)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid end date format. Use YYYY-MM-DD"})
			}
			// Add one day to include the entire end date
			endDate = endDate.Add(24 * time.Hour)
			dateFilter["$lt"] = endDate
		}

		query["appointment_date"] = dateFilter
	}

	// Configure find options
	findOptions := options.Find()
	findOptions.SetLimit(filters.Limit)
	findOptions.SetSkip(filters.Offset)
	findOptions.SetSort(bson.D{{Key: "appointment_date", Value: -1}}) // Sort by appointment date, newest first

	// Query MongoDB
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	cursor, err := appointmentsCollection.Find(c.Context(), query, findOptions)
	if err != nil {
		h.logger.Error("failed to query appointments", zap.Error(err), zap.String("doctorID", doctorID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch appointments"})
	}
	defer cursor.Close(c.Context())

	// Process appointments
	var appointments []AppointmentResponse
	for cursor.Next(c.Context()) {
		var appointment Appointment
		if err := cursor.Decode(&appointment); err != nil {
			h.logger.Error("failed to decode appointment", zap.Error(err))
			continue
		}

		// Convert to response format
		appointmentDateStr := ""
		if !appointment.AppointmentDate.IsZero() {
			appointmentDateStr = appointment.AppointmentDate.Format(time.RFC3339)
		}

		updatedAtStr := ""
		if !appointment.UpdatedAt.IsZero() {
			updatedAtStr = appointment.UpdatedAt.Format(time.RFC3339)
		}

		appointments = append(appointments, AppointmentResponse{
			PatientID:         appointment.PatientID,
			DoctorID:          appointment.DoctorID,
			HospitalID:        appointment.HospitalID,
			PatientName:       appointment.PatientName,
			DoctorName:        appointment.DoctorName,
			AppointmentStatus: appointment.AppointmentStatus,
			PaymentMethod:     appointment.PaymentMethod,
			FeeType:           appointment.FeeType,
			AppointmentFee:    appointment.AppointmentFee,
			AppointmentDate:   appointmentDateStr,
			CreatedAt:         appointment.CreatedAt.Format(time.RFC3339),
			UpdatedAt:         updatedAtStr,
		})
	}

	if err := cursor.Err(); err != nil {
		h.logger.Error("cursor error", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error processing appointments"})
	}

	// Get total count for pagination
	total, err := appointmentsCollection.CountDocuments(c.Context(), query)
	if err != nil {
		h.logger.Error("failed to count appointments", zap.Error(err))
		// Continue with the results but without total count
		total = 0
	}

	return c.JSON(fiber.Map{
		"appointments": appointments,
		"pagination": fiber.Map{
			"total":  total,
			"limit":  filters.Limit,
			"offset": filters.Offset,
		},
	})
}

// UpdateAppointment updates an existing appointment
func (h *AppointmentHandler) UpdateAppointment(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get appointment ID from params
	appointmentID := c.Params("id")
	if appointmentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Appointment ID is required"})
	}

	// Parse appointment data from request body
	var updateData map[string]interface{}
	if err := c.BodyParser(&updateData); err != nil {
		h.logger.Error("failed to parse appointment data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment data"})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Check user role
	role, err := h.getUserRole(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get user role", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	h.logger.Info("role", zap.String("role", role))
	// Update the updated_at timestamp
	updateData["updated_at"] = time.Now()

	// Convert appointment ID to ObjectID
	objID, err := primitive.ObjectIDFromHex(appointmentID)
	if err != nil {
		h.logger.Error("invalid appointment ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment ID format"})
	}

	// Update appointment in MongoDB
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	result, err := appointmentsCollection.UpdateOne(
		c.Context(),
		bson.M{"_id": objID},
		bson.M{"$set": updateData},
	)
	if err != nil {
		h.logger.Error("failed to update appointment", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update appointment"})
	}

	if result.MatchedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Appointment not found"})
	}

	return c.JSON(fiber.Map{
		"message":        "Appointment updated successfully",
		"modified_count": result.ModifiedCount,
	})
}

// DeleteAppointment deletes an existing appointment
func (h *AppointmentHandler) DeleteAppointment(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get appointment ID from params
	appointmentID := c.Params("id")
	if appointmentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Appointment ID is required"})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Check user role
	role, err := h.getUserRole(c.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get user role", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	h.logger.Info("role", zap.String("role", role))
	// Convert appointment ID to ObjectID
	objID, err := primitive.ObjectIDFromHex(appointmentID)
	if err != nil {
		h.logger.Error("invalid appointment ID format", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment ID format"})
	}

	// Delete appointment from MongoDB
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	result, err := appointmentsCollection.DeleteOne(c.Context(), bson.M{"_id": objID})
	if err != nil {
		h.logger.Error("failed to delete appointment", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete appointment"})
	}

	if result.DeletedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Appointment not found"})
	}

	return c.JSON(fiber.Map{
		"message":       "Appointment deleted successfully",
		"deleted_count": result.DeletedCount,
	})
}
