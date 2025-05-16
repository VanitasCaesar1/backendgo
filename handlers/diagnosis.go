package handlers

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.uber.org/zap"
)

// DiagnosisHandler handles diagnosis-related operations
type DiagnosisHandler struct {
	config      *config.Config
	redisClient *redis.Client
	logger      *zap.Logger
	pgPool      *pgxpool.Pool
	mongoClient *mongo.Client
}

// NewDiagnosisHandler creates a new instance of DiagnosisHandler
func NewDiagnosisHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, pgPool *pgxpool.Pool, mongoClient *mongo.Client) (*DiagnosisHandler, error) {
	usermanagement.SetAPIKey(cfg.WorkOSApiKey)
	return &DiagnosisHandler{
		config:      cfg,
		redisClient: rds,
		logger:      logger,
		pgPool:      pgPool,
		mongoClient: mongoClient,
	}, nil
}

// getAuthID extracts the authenticated user ID from the request context
func (h *DiagnosisHandler) getAuthID(c *fiber.Ctx) (string, error) {
	authID := c.Locals("authID")
	if authID == nil {
		return "", errors.New("auth ID not found in context")
	}
	return authID.(string), nil
}

// CreateDiagnosis handles the creation of a new diagnosis record
func (h *DiagnosisHandler) CreateDiagnosis(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	h.logger.Debug("Auth ID", zap.String("authID", authID))

	// Parse diagnosis data from request body
	var diagnosisRequest struct {
		AppointmentID  string   `json:"appointment_id"`
		PatientID      string   `json:"patient_id"`
		DoctorID       string   `json:"doctor_id"`
		OrgID          string   `json:"org_id"`
		Vitals         bson.M   `json:"vitals"`
		Symptoms       []bson.M `json:"symptoms"`
		DiagnosisInfo  []bson.M `json:"diagnosis_info"`
		History        bson.M   `json:"history,omitempty"`
		Status         string   `json:"status"`
		TreatmentPlan  bson.M   `json:"treatment_plan,omitempty"`
		LabDiagnostics bson.M   `json:"lab_diagnostics,omitempty"`
		Notes          string   `json:"notes,omitempty"`
		Specialization bson.M   `json:"specialization,omitempty"`
	}

	if err := c.BodyParser(&diagnosisRequest); err != nil {
		h.logger.Error("failed to parse diagnosis data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid diagnosis data: " + err.Error()})
	}

	// Log the parsed request for debugging
	h.logger.Debug("parsed diagnosis request",
		zap.String("appointment_id", diagnosisRequest.AppointmentID),
		zap.String("patient_id", diagnosisRequest.PatientID),
		zap.String("doctor_id", diagnosisRequest.DoctorID),
		zap.String("org_id", diagnosisRequest.OrgID),
		zap.String("status", diagnosisRequest.Status))

	// Check required fields individually and log which ones are missing
	var missingFields []string
	if diagnosisRequest.AppointmentID == "" {
		missingFields = append(missingFields, "appointment_id")
	}
	if diagnosisRequest.PatientID == "" {
		missingFields = append(missingFields, "patient_id")
	}
	if diagnosisRequest.DoctorID == "" {
		missingFields = append(missingFields, "doctor_id")
	}
	if diagnosisRequest.OrgID == "" {
		missingFields = append(missingFields, "org_id")
	}
	if diagnosisRequest.Vitals == nil {
		missingFields = append(missingFields, "vitals")
	} else if _, ok := diagnosisRequest.Vitals["timestamp"]; !ok {
		missingFields = append(missingFields, "vitals.timestamp")
	}
	if len(diagnosisRequest.Symptoms) == 0 {
		missingFields = append(missingFields, "symptoms")
	}
	if len(diagnosisRequest.DiagnosisInfo) == 0 {
		missingFields = append(missingFields, "diagnosis_info")
	}
	if diagnosisRequest.Status == "" {
		missingFields = append(missingFields, "status")
	}

	if len(missingFields) > 0 {
		h.logger.Error("missing specific required fields in diagnosis request",
			zap.Strings("missing_fields", missingFields))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Missing required fields: %s", strings.Join(missingFields, ", ")),
		})
	}

	// Validate ID formats based on schema requirements
	if !validatePatientID(diagnosisRequest.PatientID) {
		h.logger.Warn("invalid patient ID format", zap.String("patient_id", diagnosisRequest.PatientID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Patient ID must be 8-digit alphanumeric format"})
	}

	if !validateUUID(diagnosisRequest.DoctorID) {
		h.logger.Warn("invalid doctor ID format", zap.String("doctor_id", diagnosisRequest.DoctorID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor ID must be in UUID format"})
	}

	if !validateUUID(diagnosisRequest.AppointmentID) {
		h.logger.Warn("invalid appointment ID format", zap.String("appointment_id", diagnosisRequest.AppointmentID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Appointment ID must be in UUID format"})
	}

	if !validateOrgID(diagnosisRequest.OrgID) {
		h.logger.Warn("invalid organization ID format", zap.String("org_id", diagnosisRequest.OrgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID must be in ULID format (org_[A-Z0-9]{26})"})
	}

	// Validate status enum
	validStatuses := []string{"draft", "finalized", "amended", "cancelled"}
	statusValid := false
	for _, s := range validStatuses {
		if diagnosisRequest.Status == s {
			statusValid = true
			break
		}
	}
	if !statusValid {
		h.logger.Warn("invalid status value", zap.String("status", diagnosisRequest.Status))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Status must be one of: draft, finalized, amended, cancelled"})
	}

	// Check if appointment exists
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	var appointment bson.M
	err = appointmentsCollection.FindOne(c.Context(), bson.M{"appointment_id": diagnosisRequest.AppointmentID}).Decode(&appointment)
	if err != nil {
		h.logger.Error("appointment not found",
			zap.String("appointment_id", diagnosisRequest.AppointmentID),
			zap.Error(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Appointment not found"})
	}

	// Generate a new UUID for diagnosis_id
	diagnosisID := uuid.New().String()
	h.logger.Debug("generated diagnosis_id", zap.String("diagnosis_id", diagnosisID))

	// Create diagnosis document
	now := time.Now()
	diagnosis := bson.M{
		"diagnosis_id":   diagnosisID,
		"appointment_id": diagnosisRequest.AppointmentID,
		"patient_id":     diagnosisRequest.PatientID,
		"doctor_id":      diagnosisRequest.DoctorID,
		"org_id":         diagnosisRequest.OrgID,
		"vitals":         diagnosisRequest.Vitals,
		"symptoms":       diagnosisRequest.Symptoms,
		"diagnosis_info": diagnosisRequest.DiagnosisInfo,
		"status":         diagnosisRequest.Status,
		"created_at":     now,
		"updated_at":     now,
	}

	// Add optional fields if provided
	if diagnosisRequest.History != nil {
		diagnosis["history"] = diagnosisRequest.History
	}
	if diagnosisRequest.TreatmentPlan != nil {
		diagnosis["treatment_plan"] = diagnosisRequest.TreatmentPlan
	}
	if diagnosisRequest.LabDiagnostics != nil {
		diagnosis["lab_diagnostics"] = diagnosisRequest.LabDiagnostics
	}
	if diagnosisRequest.Notes != "" {
		diagnosis["notes"] = diagnosisRequest.Notes
	}
	if diagnosisRequest.Specialization != nil {
		diagnosis["specialization"] = diagnosisRequest.Specialization
	}

	// Log the final document we're about to insert
	h.logger.Debug("final diagnosis document for insertion", zap.Any("diagnosis", diagnosis))

	// Insert diagnosis into MongoDB
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	result, err := diagnosisCollection.InsertOne(c.Context(), diagnosis)
	if err != nil {
		h.logger.Error("failed to insert diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create diagnosis: " + err.Error()})
	}

	h.logger.Info("diagnosis created successfully",
		zap.Any("insertedID", result.InsertedID),
		zap.String("diagnosis_id", diagnosisID))

	// Add ID to diagnosis response
	diagnosis["_id"] = result.InsertedID

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":   "Diagnosis created successfully",
		"diagnosis": diagnosis,
	})
}

// GetDiagnosis retrieves a diagnosis by ID
func (h *DiagnosisHandler) GetDiagnosis(c *fiber.Ctx) error {
	diagnosisID := c.Params("id")
	if diagnosisID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Diagnosis ID is required"})
	}

	// Validate diagnosis ID format
	if !validateUUID(diagnosisID) {
		h.logger.Warn("invalid diagnosis ID format", zap.String("diagnosis_id", diagnosisID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Diagnosis ID must be in UUID format"})
	}

	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println("Auth ID", authID)
	// Query diagnosis from MongoDB
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	var diagnosis bson.M
	err = diagnosisCollection.FindOne(c.Context(), bson.M{"diagnosis_id": diagnosisID}).Decode(&diagnosis)
	if err != nil {
		h.logger.Error("diagnosis not found",
			zap.String("diagnosis_id", diagnosisID),
			zap.Error(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Diagnosis not found"})
	}

	return c.Status(fiber.StatusOK).JSON(diagnosis)
}

// UpdateDiagnosis updates an existing diagnosis
func (h *DiagnosisHandler) UpdateDiagnosis(c *fiber.Ctx) error {
	diagnosisID := c.Params("id")
	if diagnosisID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Diagnosis ID is required"})
	}

	// Validate diagnosis ID format
	if !validateUUID(diagnosisID) {
		h.logger.Warn("invalid diagnosis ID format", zap.String("diagnosis_id", diagnosisID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Diagnosis ID must be in UUID format"})
	}

	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println("Auth ID", authID)

	// Parse update data
	var updateData map[string]interface{}
	if err := c.BodyParser(&updateData); err != nil {
		h.logger.Error("failed to parse update data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid update data: " + err.Error()})
	}

	// Remove fields that cannot be updated directly
	delete(updateData, "_id")
	delete(updateData, "diagnosis_id")
	delete(updateData, "appointment_id")
	delete(updateData, "patient_id")
	delete(updateData, "doctor_id")
	delete(updateData, "org_id")
	delete(updateData, "created_at")

	// Always update the updated_at timestamp
	updateData["updated_at"] = time.Now()

	// Log update operation
	h.logger.Debug("updating diagnosis",
		zap.String("diagnosis_id", diagnosisID),
		zap.Any("update_data", updateData))

	// Update the diagnosis
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	result, err := diagnosisCollection.UpdateOne(
		c.Context(),
		bson.M{"diagnosis_id": diagnosisID},
		bson.M{"$set": updateData},
	)
	if err != nil {
		h.logger.Error("failed to update diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update diagnosis: " + err.Error()})
	}

	if result.MatchedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Diagnosis not found"})
	}

	// Get the updated diagnosis
	var updatedDiagnosis bson.M
	err = diagnosisCollection.FindOne(c.Context(), bson.M{"diagnosis_id": diagnosisID}).Decode(&updatedDiagnosis)
	if err != nil {
		h.logger.Error("failed to retrieve updated diagnosis", zap.Error(err))
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message":        "Diagnosis updated successfully, but failed to retrieve updated data",
			"modified_count": result.ModifiedCount,
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":   "Diagnosis updated successfully",
		"diagnosis": updatedDiagnosis,
	})
}

// DeleteDiagnosis deletes a diagnosis by ID
func (h *DiagnosisHandler) DeleteDiagnosis(c *fiber.Ctx) error {
	diagnosisID := c.Params("id")
	if diagnosisID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Diagnosis ID is required"})
	}

	// Validate diagnosis ID format
	if !validateUUID(diagnosisID) {
		h.logger.Warn("invalid diagnosis ID format", zap.String("diagnosis_id", diagnosisID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Diagnosis ID must be in UUID format"})
	}

	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println("Auth ID", authID)

	// Delete the diagnosis
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	result, err := diagnosisCollection.DeleteOne(c.Context(), bson.M{"diagnosis_id": diagnosisID})
	if err != nil {
		h.logger.Error("failed to delete diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete diagnosis: " + err.Error()})
	}

	if result.DeletedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Diagnosis not found"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":       "Diagnosis deleted successfully",
		"deleted_count": result.DeletedCount,
	})
}

// ListDiagnoses retrieves diagnoses with optional filtering
func (h *DiagnosisHandler) ListDiagnoses(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println("Auth ID", authID)

	// Parse query parameters
	patientID := c.Query("patient_id")
	doctorID := c.Query("doctor_id")
	appointmentID := c.Query("appointment_id")
	status := c.Query("status")

	// Build filter
	filter := bson.M{}
	if patientID != "" {
		filter["patient_id"] = patientID
	}
	if doctorID != "" {
		filter["doctor_id"] = doctorID
	}
	if appointmentID != "" {
		filter["appointment_id"] = appointmentID
	}
	if status != "" {
		filter["status"] = status
	}

	// Parse pagination parameters
	page, err := strconv.Atoi(c.Query("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(c.Query("limit", "10"))
	if err != nil || limit < 1 || limit > 100 {
		limit = 10
	}
	skip := (page - 1) * limit

	// Query options
	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(skip)).
		SetSort(bson.M{"created_at": -1}) // Sort by most recent first

	// Query diagnoses from MongoDB
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	cursor, err := diagnosisCollection.Find(c.Context(), filter, opts)
	if err != nil {
		h.logger.Error("failed to query diagnoses", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve diagnoses"})
	}
	defer cursor.Close(c.Context())

	// Decode results
	var diagnoses []bson.M
	if err := cursor.All(c.Context(), &diagnoses); err != nil {
		h.logger.Error("failed to decode diagnoses", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode diagnoses"})
	}

	// Count total documents for pagination
	total, err := diagnosisCollection.CountDocuments(c.Context(), filter)
	if err != nil {
		h.logger.Error("failed to count diagnoses", zap.Error(err))
		total = int64(len(diagnoses)) // Fallback to length of results
	}

	// Calculate pagination info
	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	hasNext := page < totalPages
	hasPrev := page > 1

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"diagnoses": diagnoses,
		"pagination": fiber.Map{
			"total":       total,
			"page":        page,
			"limit":       limit,
			"total_pages": totalPages,
			"has_next":    hasNext,
			"has_prev":    hasPrev,
		},
	})
}
