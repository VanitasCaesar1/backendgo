package handlers

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/go-playground/validator/v10"
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
	validator   *validator.Validate
}

type DiagnosisRequest struct {
	AppointmentID  string       `json:"appointment_id" validate:"required,uuid"`
	PatientID      string       `json:"patient_id" validate:"required"`
	DoctorID       string       `json:"doctor_id" validate:"required,uuid"`
	OrgID          string       `json:"org_id" validate:"required"`
	Vitals         VitalsData   `json:"vitals" validate:"required"`
	Symptoms       []Symptom    `json:"symptoms" validate:"required,min=1,dive"`
	DiagnosisInfo  []Diagnosis  `json:"diagnosis_info" validate:"required,min=1,dive"`
	History        *History     `json:"history,omitempty"`
	Status         string       `json:"status" validate:"required,oneof=draft finalized amended cancelled"`
	TreatmentPlan  *Treatment   `json:"treatment_plan,omitempty"`
	LabDiagnostics *LabTests    `json:"lab_diagnostics,omitempty"`
	Notes          string       `json:"notes,omitempty"`
	Specialization *Specialty   `json:"specialization,omitempty"`
	Attachments    []Attachment `json:"attachments,omitempty"`
}

// VitalsData represents vital signs data
type VitalsData struct {
	Timestamp        time.Time `json:"timestamp" validate:"required"`
	Temperature      *float64  `json:"temperature,omitempty"`
	TemperatureUnit  *string   `json:"temperature_unit,omitempty" validate:"omitempty,oneof=F C"`
	BloodPressure    *string   `json:"blood_pressure,omitempty"`
	HeartRate        *int      `json:"heart_rate,omitempty"`
	RespiratoryRate  *int      `json:"respiratory_rate,omitempty"`
	Weight           *float64  `json:"weight,omitempty"`
	WeightUnit       *string   `json:"weight_unit,omitempty" validate:"omitempty,oneof=kg lb"`
	Height           *float64  `json:"height,omitempty"`
	HeightUnit       *string   `json:"height_unit,omitempty" validate:"omitempty,oneof=cm in"`
	BMI              *float64  `json:"bmi,omitempty"`
	BloodGlucose     *float64  `json:"blood_glucose,omitempty"`
	BloodGlucoseUnit *string   `json:"blood_glucose_unit,omitempty" validate:"omitempty,oneof=mg/dL mmol/L"`
	OxygenSaturation *float64  `json:"oxygen_saturation,omitempty"`
	PainLevel        *int      `json:"pain_level,omitempty" validate:"omitempty,min=0,max=10"`
}

// Symptom represents a patient symptom
type Symptom struct {
	Name               string   `json:"name" validate:"required"`
	Since              *string  `json:"since,omitempty"`
	Severity           *string  `json:"severity,omitempty" validate:"omitempty,oneof=mild moderate severe"`
	Location           *string  `json:"location,omitempty"`
	Character          *string  `json:"character,omitempty"`
	AlleviatingFactors *string  `json:"alleviating_factors,omitempty"`
	AggravatingFactors *string  `json:"aggravating_factors,omitempty"`
	AssociatedSymptoms []string `json:"associated_symptoms,omitempty"`
	Notes              *string  `json:"notes,omitempty"`
}

// Diagnosis represents a medical diagnosis
type Diagnosis struct {
	Name                  string   `json:"name" validate:"required"`
	ICDCode               *string  `json:"icd_code,omitempty"`
	Since                 *string  `json:"since,omitempty"`
	Status                string   `json:"status" validate:"required,oneof=provisional working confirmed ruled_out"`
	Notes                 *string  `json:"notes,omitempty"`
	SupportingFactors     []string `json:"supporting_factors,omitempty"`
	DifferentialDiagnoses []string `json:"differential_diagnoses,omitempty"`
}

// History represents patient medical history
type History struct {
	MedicalHistory  *string        `json:"medical_history,omitempty"`
	FamilyHistory   *string        `json:"family_history,omitempty"`
	Allergies       []Allergy      `json:"allergies,omitempty"`
	SurgicalHistory []Surgery      `json:"surgical_history,omitempty"`
	SocialHistory   *SocialHistory `json:"social_history,omitempty"`
}

// Allergy represents an allergic reaction
type Allergy struct {
	Allergen string  `json:"allergen" validate:"required"`
	Reaction *string `json:"reaction,omitempty"`
	Severity *string `json:"severity,omitempty" validate:"omitempty,oneof=mild moderate severe"`
}

// Surgery represents surgical history
type Surgery struct {
	Procedure string     `json:"procedure,omitempty"`
	Date      *time.Time `json:"date,omitempty"`
	Notes     *string    `json:"notes,omitempty"`
}

// SocialHistory represents social history
type SocialHistory struct {
	TobaccoUse *bool   `json:"tobacco_use,omitempty"`
	AlcoholUse *bool   `json:"alcohol_use,omitempty"`
	DrugUse    *bool   `json:"drug_use,omitempty"`
	Notes      *string `json:"notes,omitempty"`
}

// Treatment represents treatment plan
type Treatment struct {
	Medications      []Medication `json:"medications,omitempty"`
	Procedures       []Procedure  `json:"procedures,omitempty"`
	LifestyleChanges []string     `json:"lifestyle_changes,omitempty"`
	FollowUp         *FollowUp    `json:"follow_up,omitempty"`
	Referrals        []Referral   `json:"referrals,omitempty"`
}

// Medication represents prescribed medication
type Medication struct {
	Name         string  `json:"name" validate:"required"`
	GenericName  *string `json:"generic_name,omitempty"`
	Dosage       string  `json:"dosage" validate:"required"`
	Route        *string `json:"route,omitempty"`
	Frequency    string  `json:"frequency" validate:"required"`
	Duration     *string `json:"duration,omitempty"`
	Instructions *string `json:"instructions,omitempty"`
}

// Procedure represents medical procedure
type Procedure struct {
	Name  string     `json:"name" validate:"required"`
	Date  *time.Time `json:"date,omitempty"`
	Notes *string    `json:"notes,omitempty"`
}

// FollowUp represents follow-up instructions
type FollowUp struct {
	Date     *time.Time `json:"date,omitempty"`
	Duration *string    `json:"duration,omitempty"`
	Notes    *string    `json:"notes,omitempty"`
}

// Referral represents specialist referral
type Referral struct {
	Specialist string  `json:"specialist" validate:"required"`
	Reason     *string `json:"reason,omitempty"`
	Urgency    *string `json:"urgency,omitempty" validate:"omitempty,oneof=routine urgent emergency"`
}

// LabTests represents laboratory diagnostics
type LabTests struct {
	OrderedTests []OrderedTest `json:"ordered_tests,omitempty"`
	TestResults  []TestResult  `json:"test_results,omitempty"`
}

// OrderedTest represents an ordered test
type OrderedTest struct {
	Name   string  `json:"name" validate:"required"`
	Status *string `json:"status,omitempty" validate:"omitempty,oneof=ordered completed pending cancelled"`
	Notes  *string `json:"notes,omitempty"`
}

// TestResult represents test results
type TestResult struct {
	Name           string      `json:"name" validate:"required"`
	Date           time.Time   `json:"date" validate:"required"`
	Result         interface{} `json:"result,omitempty"`
	Interpretation *string     `json:"interpretation,omitempty"`
	ReferenceRange *string     `json:"reference_range,omitempty"`
}

// Specialty represents specialty-specific information
type Specialty struct {
	SpecialtyType string      `json:"specialty_type,omitempty" validate:"omitempty,oneof=general_medicine cardiology neurology orthopedics pediatrics dermatology ophthalmology ent gynecology urology psychiatry endocrinology gastroenterology oncology pulmonology nephrology rheumatology other"`
	CustomFields  interface{} `json:"custom_fields,omitempty"`
}

// Attachment represents file attachments
type Attachment struct {
	FileID      string     `json:"file_id" validate:"required"`
	FileName    string     `json:"file_name" validate:"required"`
	FileType    string     `json:"file_type" validate:"required"`
	Description *string    `json:"description,omitempty"`
	UploadDate  *time.Time `json:"upload_date,omitempty"`
}

func NewDiagnosisHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, pgPool *pgxpool.Pool, mongoClient *mongo.Client) (*DiagnosisHandler, error) {
	usermanagement.SetAPIKey(cfg.WorkOSApiKey)
	return &DiagnosisHandler{
		config:      cfg,
		redisClient: rds,
		logger:      logger,
		pgPool:      pgPool,
		mongoClient: mongoClient,
		validator:   validator.New(),
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
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
	}
	h.logger.Debug("Auth ID", zap.String("authID", authID))

	// Parse update data from request body
	var updateRequest DiagnosisRequest
	if err := c.BodyParser(&updateRequest); err != nil {
		h.logger.Error("failed to parse update data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
	}

	// Validate the request using the validator (optional fields will be ignored if empty)
	if err := h.validator.Struct(&updateRequest); err != nil {
		h.logger.Error("validation failed", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": formatValidationErrors(err),
		})
	}

	// Check if diagnosis exists first
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	var existingDiagnosis bson.M
	err = diagnosisCollection.FindOne(c.Context(), bson.M{"diagnosis_id": diagnosisID}).Decode(&existingDiagnosis)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Diagnosis not found"})
		}
		h.logger.Error("failed to find diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	// Additional custom validations if needed
	if updateRequest.PatientID != "" || updateRequest.DoctorID != "" ||
		updateRequest.AppointmentID != "" || updateRequest.OrgID != "" {
		if err := h.validateDiagnosisRequest(&updateRequest); err != nil {
			h.logger.Error("custom validation failed", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
	}

	// Build update document
	updateDoc := bson.M{}
	now := time.Now()

	// Only update fields that are provided in the request
	if updateRequest.Vitals.Timestamp != (time.Time{}) {
		updateDoc["vitals"] = updateRequest.Vitals
	}
	if len(updateRequest.Symptoms) > 0 {
		updateDoc["symptoms"] = updateRequest.Symptoms
	}
	if len(updateRequest.DiagnosisInfo) > 0 {
		updateDoc["diagnosis_info"] = updateRequest.DiagnosisInfo
	}
	if updateRequest.Status != "" {
		updateDoc["status"] = updateRequest.Status
	}
	if updateRequest.History != nil {
		updateDoc["history"] = updateRequest.History
	}
	if updateRequest.TreatmentPlan != nil {
		updateDoc["treatment_plan"] = updateRequest.TreatmentPlan
	}
	if updateRequest.LabDiagnostics != nil {
		updateDoc["lab_diagnostics"] = updateRequest.LabDiagnostics
	}
	if updateRequest.Notes != "" {
		updateDoc["notes"] = updateRequest.Notes
	}
	if updateRequest.Specialization != nil {
		updateDoc["specialization"] = updateRequest.Specialization
	}
	if len(updateRequest.Attachments) > 0 {
		updateDoc["attachments"] = updateRequest.Attachments
	}

	// Always update the updated_at timestamp
	updateDoc["updated_at"] = now

	// Log update operation
	h.logger.Debug("updating diagnosis",
		zap.String("diagnosis_id", diagnosisID),
		zap.Any("update_fields", updateDoc))

	// Perform the update operation directly
	result, err := diagnosisCollection.UpdateOne(
		c.Context(),
		bson.M{"diagnosis_id": diagnosisID},
		bson.M{"$set": updateDoc},
	)

	if err != nil {
		h.logger.Error("failed to update diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update diagnosis"})
	}

	if result.MatchedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Diagnosis not found"})
	}

	h.logger.Info("diagnosis updated successfully",
		zap.String("diagnosis_id", diagnosisID),
		zap.Int64("modified_count", result.ModifiedCount))

	// Get the updated diagnosis
	var updatedDiagnosis bson.M
	err = diagnosisCollection.FindOne(c.Context(), bson.M{"diagnosis_id": diagnosisID}).Decode(&updatedDiagnosis)
	if err != nil {
		h.logger.Error("failed to retrieve updated diagnosis", zap.Error(err))
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message":        "Diagnosis updated successfully",
			"modified_count": result.ModifiedCount,
			"updated_at":     now,
		})
	}

	// Prepare response
	response := fiber.Map{
		"message":        "Diagnosis updated successfully",
		"diagnosis_id":   diagnosisID,
		"modified_count": result.ModifiedCount,
		"updated_at":     now,
		"diagnosis":      updatedDiagnosis,
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// CreateDiagnosis handles the creation of a new diagnosis record
func (h *DiagnosisHandler) CreateDiagnosis(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
	}
	h.logger.Debug("Auth ID", zap.String("authID", authID))

	// Parse diagnosis data from request body
	var diagnosisRequest DiagnosisRequest
	if err := c.BodyParser(&diagnosisRequest); err != nil {
		h.logger.Error("failed to parse diagnosis data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
	}

	// Validate the request using the validator
	if err := h.validator.Struct(&diagnosisRequest); err != nil {
		h.logger.Error("validation failed", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": formatValidationErrors(err),
		})
	}

	// Log the parsed request for debugging
	h.logger.Debug("parsed diagnosis request",
		zap.String("appointment_id", diagnosisRequest.AppointmentID),
		zap.String("patient_id", diagnosisRequest.PatientID),
		zap.String("doctor_id", diagnosisRequest.DoctorID),
		zap.String("org_id", diagnosisRequest.OrgID),
		zap.String("status", diagnosisRequest.Status))

	// Additional custom validations
	if err := h.validateDiagnosisRequest(&diagnosisRequest); err != nil {
		h.logger.Error("custom validation failed", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Check if appointment exists and belongs to the organization
	if err := h.validateAppointmentExists(c, diagnosisRequest.AppointmentID, diagnosisRequest.OrgID); err != nil {
		return err
	}

	// Check for existing diagnosis for this appointment
	if exists, err := h.checkExistingDiagnosis(c, diagnosisRequest.AppointmentID); err != nil {
		h.logger.Error("failed to check existing diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	} else if exists {
		h.logger.Warn("diagnosis already exists for appointment", zap.String("appointment_id", diagnosisRequest.AppointmentID))
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Diagnosis already exists for this appointment"})
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
	if len(diagnosisRequest.Attachments) > 0 {
		diagnosis["attachments"] = diagnosisRequest.Attachments
	}

	// Insert the diagnosis directly
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	result, err := diagnosisCollection.InsertOne(c.Context(), diagnosis)

	if err != nil {
		h.logger.Error("failed to insert diagnosis", zap.Error(err))
		if mongo.IsDuplicateKeyError(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Diagnosis with this ID already exists"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create diagnosis"})
	}

	h.logger.Info("diagnosis created successfully",
		zap.Any("insertedID", result.InsertedID),
		zap.String("diagnosis_id", diagnosisID),
		zap.String("appointment_id", diagnosisRequest.AppointmentID))

	// Prepare response
	response := fiber.Map{
		"message":      "Diagnosis created successfully",
		"diagnosis_id": diagnosisID,
		"created_at":   now,
		"status":       diagnosisRequest.Status,
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

// validateDiagnosisRequest performs custom validation
func (h *DiagnosisHandler) validateDiagnosisRequest(req *DiagnosisRequest) error {
	// Validate ID formats based on schema requirements
	if !validatePatientID(req.PatientID) {
		return fmt.Errorf("patient ID must be 8-digit alphanumeric format")
	}

	if !validateUUID(req.DoctorID) {
		return fmt.Errorf("doctor ID must be in UUID format")
	}

	if !validateUUID(req.AppointmentID) {
		return fmt.Errorf("appointment ID must be in UUID format")
	}

	if !validateOrgID(req.OrgID) {
		return fmt.Errorf("organization ID must be in ULID format (org_[A-Z0-9]{26})")
	}

	// Validate vitals timestamp
	if req.Vitals.Timestamp.IsZero() {
		return fmt.Errorf("vitals timestamp is required")
	}

	// Validate temperature unit if temperature is provided
	if req.Vitals.Temperature != nil && req.Vitals.TemperatureUnit == nil {
		return fmt.Errorf("temperature unit is required when temperature is provided")
	}

	// Validate weight unit if weight is provided
	if req.Vitals.Weight != nil && req.Vitals.WeightUnit == nil {
		return fmt.Errorf("weight unit is required when weight is provided")
	}

	// Validate height unit if height is provided
	if req.Vitals.Height != nil && req.Vitals.HeightUnit == nil {
		return fmt.Errorf("height unit is required when height is provided")
	}

	// Validate blood glucose unit if blood glucose is provided
	if req.Vitals.BloodGlucose != nil && req.Vitals.BloodGlucoseUnit == nil {
		return fmt.Errorf("blood glucose unit is required when blood glucose is provided")
	}

	return nil
}

// validateAppointmentExists checks if appointment exists and belongs to org
func (h *DiagnosisHandler) validateAppointmentExists(c *fiber.Ctx, appointmentID, orgID string) error {
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")

	filter := bson.M{
		"appointment_id": appointmentID,
		"org_id":         orgID,
	}

	var appointment bson.M
	err := appointmentsCollection.FindOne(c.Context(), filter).Decode(&appointment)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			h.logger.Warn("appointment not found or doesn't belong to organization",
				zap.String("appointment_id", appointmentID),
				zap.String("org_id", orgID))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Appointment not found"})
		}
		h.logger.Error("error checking appointment", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	return nil
}

// checkExistingDiagnosis checks if diagnosis already exists for appointment
func (h *DiagnosisHandler) checkExistingDiagnosis(c *fiber.Ctx, appointmentID string) (bool, error) {
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")

	count, err := diagnosisCollection.CountDocuments(c.Context(), bson.M{"appointment_id": appointmentID})
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// formatValidationErrors formats validation errors for better response
func formatValidationErrors(err error) interface{} {
	var validationErrors []map[string]string

	if ve, ok := err.(validator.ValidationErrors); ok {
		for _, fe := range ve {
			validationErrors = append(validationErrors, map[string]string{
				"field":   fe.Field(),
				"tag":     fe.Tag(),
				"value":   fmt.Sprintf("%v", fe.Value()),
				"message": getValidationMessage(fe),
			})
		}
		return validationErrors
	}

	return err.Error()
}

// getValidationMessage returns user-friendly validation messages
func getValidationMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", fe.Field())
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", fe.Field(), fe.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", fe.Field(), fe.Param())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", fe.Field())
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", fe.Field())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", fe.Field(), fe.Param())
	default:
		return fmt.Sprintf("%s is invalid", fe.Field())
	}
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
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
	}
	h.logger.Debug("Auth ID", zap.String("authID", authID))

	// Check if diagnosis exists first
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	var existingDiagnosis bson.M
	err = diagnosisCollection.FindOne(c.Context(), bson.M{"diagnosis_id": diagnosisID}).Decode(&existingDiagnosis)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Diagnosis not found"})
		}
		h.logger.Error("failed to find diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	h.logger.Debug("found diagnosis to delete",
		zap.String("diagnosis_id", diagnosisID),
		zap.String("appointment_id", fmt.Sprintf("%v", existingDiagnosis["appointment_id"])))

	// Perform the delete operation directly
	result, err := diagnosisCollection.DeleteOne(c.Context(), bson.M{"diagnosis_id": diagnosisID})

	if err != nil {
		h.logger.Error("failed to delete diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete diagnosis"})
	}

	if result.DeletedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Diagnosis not found"})
	}

	h.logger.Info("diagnosis deleted successfully",
		zap.String("diagnosis_id", diagnosisID),
		zap.Int64("deleted_count", result.DeletedCount))

	// Prepare response
	response := fiber.Map{
		"message":       "Diagnosis deleted successfully",
		"diagnosis_id":  diagnosisID,
		"deleted_count": result.DeletedCount,
		"deleted_at":    time.Now(),
	}

	return c.Status(fiber.StatusOK).JSON(response)
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
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
	}
	h.logger.Debug("Auth ID", zap.String("authID", authID))

	// Retrieve diagnosis from MongoDB
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	var diagnosis bson.M
	err = diagnosisCollection.FindOne(c.Context(), bson.M{"diagnosis_id": diagnosisID}).Decode(&diagnosis)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Diagnosis not found"})
		}
		h.logger.Error("failed to retrieve diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	h.logger.Debug("diagnosis retrieved successfully", zap.String("diagnosis_id", diagnosisID))

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":   "Diagnosis retrieved successfully",
		"diagnosis": diagnosis,
	})
}

// ListDiagnoses retrieves diagnoses with optional filtering
func (h *DiagnosisHandler) ListDiagnoses(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
	}
	h.logger.Debug("Auth ID", zap.String("authID", authID))

	// Parse query parameters
	orgID := c.Query("org_id")
	patientID := c.Query("patient_id")
	doctorID := c.Query("doctor_id")
	status := c.Query("status")
	appointmentID := c.Query("appointment_id")

	// Pagination parameters
	page, _ := strconv.Atoi(c.Query("page", "1"))
	limit, _ := strconv.Atoi(c.Query("limit", "10"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}
	skip := (page - 1) * limit

	// Build filter
	filter := bson.M{}
	if orgID != "" {
		filter["org_id"] = orgID
	}
	if patientID != "" {
		filter["patient_id"] = patientID
	}
	if doctorID != "" {
		filter["doctor_id"] = doctorID
	}
	if status != "" {
		filter["status"] = status
	}
	if appointmentID != "" {
		filter["appointment_id"] = appointmentID
	}

	// Set up collection and options
	diagnosisCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")
	findOptions := options.Find()
	findOptions.SetSkip(int64(skip))
	findOptions.SetLimit(int64(limit))
	findOptions.SetSort(bson.D{{Key: "created_at", Value: -1}}) // Sort by creation date, newest first

	// Execute query
	cursor, err := diagnosisCollection.Find(c.Context(), filter, findOptions)
	if err != nil {
		h.logger.Error("failed to retrieve diagnoses", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}
	defer cursor.Close(c.Context())

	// Decode results
	var diagnoses []bson.M
	if err = cursor.All(c.Context(), &diagnoses); err != nil {
		h.logger.Error("failed to decode diagnoses", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	// Get total count for pagination
	totalCount, err := diagnosisCollection.CountDocuments(c.Context(), filter)
	if err != nil {
		h.logger.Error("failed to count diagnoses", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	totalPages := int(math.Ceil(float64(totalCount) / float64(limit)))

	h.logger.Debug("diagnoses retrieved successfully",
		zap.Int("count", len(diagnoses)),
		zap.Int64("total", totalCount),
		zap.Int("page", page))

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":   "Diagnoses retrieved successfully",
		"diagnoses": diagnoses,
		"pagination": fiber.Map{
			"page":        page,
			"limit":       limit,
			"total":       totalCount,
			"total_pages": totalPages,
			"has_next":    page < totalPages,
			"has_prev":    page > 1,
		},
	})
}

// MedicalHistoryRecord represents a diagnosis record for medical history
type MedicalHistoryRecord struct {
	ID                 string                `json:"id" bson:"diagnosis_id"`
	DiagnosisName      string                `json:"diagnosis_name" bson:"diagnosis_name"`
	PrimaryDiagnosis   string                `json:"primary_diagnosis" bson:"primary_diagnosis"`
	SecondaryDiagnoses []string              `json:"secondary_diagnoses,omitempty" bson:"secondary_diagnoses"`
	Symptoms           []string              `json:"symptoms,omitempty" bson:"symptoms"`
	Severity           string                `json:"severity,omitempty" bson:"severity"`
	Status             string                `json:"status" bson:"status"`
	DiagnosisDate      time.Time             `json:"diagnosis_date" bson:"diagnosis_date"`
	Notes              string                `json:"notes,omitempty" bson:"notes"`
	Prescriptions      []PrescriptionHistory `json:"prescriptions,omitempty" bson:"prescriptions"`
	CreatedAt          time.Time             `json:"created_at" bson:"created_at"`
	// Note: Deliberately excluding doctor_id, doctor_name, org_id for privacy
}

// PrescriptionHistory represents prescription data for medical history
type PrescriptionHistory struct {
	MedicationName string `json:"medication_name" bson:"medication_name"`
	Dosage         string `json:"dosage" bson:"dosage"`
	Frequency      string `json:"frequency" bson:"frequency"`
	Duration       string `json:"duration,omitempty" bson:"duration"`
	Instructions   string `json:"instructions,omitempty" bson:"instructions"`
}

// MedicalHistoryResponse represents the response structure
type MedicalHistoryResponse struct {
	PatientID string                 `json:"patient_id"`
	History   []MedicalHistoryRecord `json:"history"`
	Total     int64                  `json:"total"`
}

// GetPatientMedicalHistory fetches comprehensive medical history for a patient
func (h *DiagnosisHandler) GetPatientMedicalHistory(c *fiber.Ctx) error {
	// Get organization ID from headers (required for authentication)
	orgID := c.Get("X-Organization-ID")
	if orgID == "" {
		h.logger.Warn("missing organization ID in request headers")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Organization ID is required",
		})
	}

	// Get user role from headers for authorization
	userRole := c.Get("X-User-Role")
	userID := c.Get("X-User-ID")

	// Log the authenticated request
	h.logger.Info("Received medical history request",
		zap.String("orgID", orgID),
		zap.String("userRole", userRole),
		zap.String("userID", userID))

	// Get patient ID from URL params
	patientID := c.Params("id")
	if patientID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Patient ID is required",
		})
	}

	// Validate patient ID format (8-digit alphanumeric)
	if !isValidPatientID(patientID) {
		h.logger.Error("invalid patient ID format", zap.String("patient_id", patientID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid patient ID format",
		})
	}

	// Get optional query parameters
	limit := c.QueryInt("limit", 50)
	if limit > 100 {
		limit = 100 // Cap at 100 records
	}
	includeActive := c.QueryBool("include_active", true)

	// Build MongoDB query
	filter := bson.M{"patient_id": patientID}

	// Add organization filter if not cross-org request
	crossOrg := c.QueryBool("cross_org", false)
	if !crossOrg {
		filter["organization_id"] = orgID
	}

	// Optionally exclude active/draft diagnoses
	if !includeActive {
		filter["status"] = bson.M{"$ne": "draft"}
	}

	// Get diagnoses collection
	diagnosesCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("diagnoses")

	// Set up options for sorting and limiting
	// FIXED: Use bson.D instead of bson.M for ordered sort parameters
	opts := options.Find().
		SetSort(bson.D{
			{"diagnosis_date", -1},
			{"created_at", -1},
		}). // Most recent first
		SetLimit(int64(limit))

	// Execute query
	cursor, err := diagnosesCollection.Find(c.Context(), filter, opts)
	if err != nil {
		h.logger.Error("failed to fetch medical history",
			zap.Error(err),
			zap.String("patient_id", patientID),
			zap.String("organization_id", orgID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch medical history",
		})
	}
	defer cursor.Close(c.Context())

	// Decode results
	var diagnoses []MedicalHistoryRecord
	if err = cursor.All(c.Context(), &diagnoses); err != nil {
		h.logger.Error("failed to decode medical history",
			zap.Error(err),
			zap.String("patient_id", patientID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process medical history",
		})
	}

	// Get total count for pagination info
	totalCount, err := diagnosesCollection.CountDocuments(c.Context(), filter)
	if err != nil {
		h.logger.Warn("failed to get total count", zap.Error(err))
		totalCount = int64(len(diagnoses))
	}

	// Log successful response
	h.logger.Info("Successfully retrieved medical history",
		zap.String("patient_id", patientID),
		zap.String("organization_id", orgID),
		zap.Int("record_count", len(diagnoses)),
		zap.Int64("total_count", totalCount))

	// Format response
	response := MedicalHistoryResponse{
		PatientID: patientID,
		History:   diagnoses,
		Total:     totalCount,
	}

	return c.JSON(response)
}

// Helper function to validate patient ID format (8-digit alphanumeric)
func isValidPatientID(patientID string) bool {
	if len(patientID) != 8 {
		return false
	}
	for _, char := range patientID {
		if !((char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			return false
		}
	}
	return true
}
