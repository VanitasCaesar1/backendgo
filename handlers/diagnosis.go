package handlers

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/zap"
)

type DiagnosisHandler struct {
	pgPool      *pgxpool.Pool
	config      *config.Config
	mongoClient *mongo.Client // MongoDB connection for appointments
	logger      *zap.Logger
}

type DiagnosisRequest struct {
	AppointmentID   string  `json:"appointment_id" validate:"required,uuid"`
	PatientID       string  `json:"patient_id" validate:"required"`
	DoctorID        string  `json:"doctor_id" validate:"required,uuid"`
	OrgID           string  `json:"org_id" validate:"required"`
	PatientName     *string `json:"patient_name,omitempty"`
	PatientAge      *int    `json:"patient_age,omitempty"`
	PatientGender   *string `json:"patient_gender,omitempty" validate:"omitempty,oneof=male female other"`
	DoctorName      *string `json:"doctor_name,omitempty"`
	DoctorSpecialty *string `json:"doctor_specialty,omitempty"`
	// Vitals - directly in the struct, not nested
	Temperature      *float64 `json:"temperature,string"`
	BloodPressure    string   `json:"blood_pressure"`
	HeartRate        *int     `json:"heart_rate,string"`
	Weight           *float64 `json:"weight,string"`
	Height           *float64 `json:"height"`
	BMI              *float64 `json:"bmi"`
	RespiratoryRate  *int     `json:"respiratory_rate,string"`
	OxygenSaturation *int     `json:"oxygen_saturation,string"`

	ChiefComplaint     *string          `json:"chief_complaint,omitempty"`
	Symptoms           []Symptom        `json:"symptoms" validate:"required,min=1,dive"`
	PhysicalExam       *string          `json:"physical_exam,omitempty"`
	PrimaryDiagnosis   string           `json:"primary_diagnosis" validate:"required"`
	SecondaryDiagnoses []string         `json:"secondary_diagnoses,omitempty"`
	ICDCodes           []string         `json:"icd_codes,omitempty"`
	Status             string           `json:"status" validate:"required,oneof=draft finalized amended"`
	TreatmentPlan      *Treatment       `json:"treatment_plan,omitempty"`
	LabOrders          []string         `json:"lab_orders,omitempty"`
	TestResults        []TestResult     `json:"test_results,omitempty"`
	Specialty          *string          `json:"specialty,omitempty"`
	Medications        []Medication     `json:"medications"`
	Procedures         []string         `json:"procedures"`
	Recommendations    string           `json:"recommendations"`
	SpecialtyData      *json.RawMessage `json:"specialty_data,omitempty"`
	FollowUpDate       *time.Time       `json:"follow_up_date,omitempty"`
	FollowUpNotes      *string          `json:"follow_up_notes,omitempty"`
	Referrals          []string         `json:"referrals,omitempty"`
	ClinicalNotes      *string          `json:"clinical_notes,omitempty"`
	Attachments        []Attachment     `json:"attachments,omitempty"`
}

// VitalsData represents vital signs data
type VitalsData struct {
	Temperature   *float64 `json:"temperature,omitempty"`
	BloodPressure *string  `json:"blood_pressure,omitempty"`
	HeartRate     *int     `json:"heart_rate,omitempty"`
	Weight        *float64 `json:"weight,omitempty"`
	Height        *float64 `json:"height,omitempty"`
	BMI           *float64 `json:"bmi,omitempty"`
}

// Treatment represents treatment plan
type Treatment struct {
	Medications     []Medication `json:"medications,omitempty"`
	Procedures      []string     `json:"procedures,omitempty"`
	Recommendations *string      `json:"recommendations,omitempty"`
}

// Implement Valuer interface for PostgreSQL JSON fields
func (s Symptom) Value() (driver.Value, error) {
	return json.Marshal(s)
}

func (t Treatment) Value() (driver.Value, error) {
	return json.Marshal(t)
}

func (tr TestResult) Value() (driver.Value, error) {
	return json.Marshal(tr)
}

func (a Attachment) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// Option 1: Return both handler and error (Recommended)
func NewDiagnosisHandler(pgPool *pgxpool.Pool, mongoClient *mongo.Client, logger *zap.Logger, cfg *config.Config) (*DiagnosisHandler, error) {
	// Add validation logic here if needed
	if pgPool == nil {
		return nil, errors.New("postgres pool cannot be nil")
	}
	if mongoClient == nil {
		return nil, errors.New("mongo client cannot be nil")
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}

	return &DiagnosisHandler{
		pgPool: pgPool,
		config: cfg,

		mongoClient: mongoClient,
		logger:      logger,
	}, nil
}

// Option 2: Alternative constructor that only returns handler (if you prefer no error handling)
func NewDiagnosisHandlerNoError(pgPool *pgxpool.Pool, mongoClient *mongo.Client, logger *zap.Logger) *DiagnosisHandler {
	return &DiagnosisHandler{
		pgPool:      pgPool,
		mongoClient: mongoClient,
		logger:      logger,
	}
}

// getAuthID extracts the authenticated user ID from the request context
func (h *DiagnosisHandler) getAuthID(c *fiber.Ctx) (string, error) {
	authID := c.Locals("authID")
	if authID == nil {
		return "", errors.New("auth ID not found in context")
	}
	return authID.(string), nil
}

// validateDiagnosisRequest performs custom validation
func (h *DiagnosisHandler) validateDiagnosisRequest(req *DiagnosisRequest) error {
	// Validate UUID fields
	if req.AppointmentID != "" && !validateUUID(req.AppointmentID) {
		return errors.New("invalid appointment ID format")
	}
	if req.DoctorID != "" && !validateUUID(req.DoctorID) {
		return errors.New("invalid doctor ID format")
	}

	// Validate vitals ranges
	if req.Temperature != nil && (*req.Temperature < 35.0 || *req.Temperature > 43.0) {
		return errors.New("temperature must be between 95.0 and 110.0")
	}
	if req.HeartRate != nil && (*req.HeartRate < 30 || *req.HeartRate > 250) {
		return errors.New("heart rate must be between 30 and 250")
	}
	if req.BMI != nil && (*req.BMI < 10.0 || *req.BMI > 60.0) {
		return errors.New("BMI must be between 10.0 and 60.0")
	}

	return nil
}

// validateAppointmentExists checks if appointment exists and belongs to the organization
func (h *DiagnosisHandler) validateAppointmentExists(c *fiber.Ctx, appointmentID, orgID string) error {
	// Get appointments collection
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")

	// Clean the appointment ID - remove whitespace and convert to lowercase
	appointmentID = strings.ToLower(strings.TrimSpace(appointmentID))

	// Validate UUID format
	if !isValidUUID(appointmentID) {
		h.logger.Error("invalid appointment ID format", zap.String("id", appointmentID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment ID format"})
	}

	// Create filter for both appointment_id and org_id
	filter := bson.M{
		"appointment_id": bson.M{"$regex": "^" + appointmentID + "$", "$options": "i"},
		"org_id":         orgID,
		"is_valid":       true, // Only check valid appointments
	}

	// Count documents matching the filter
	count, err := appointmentsCollection.CountDocuments(c.Context(), filter)
	if err != nil {
		h.logger.Error("failed to validate appointment", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	if count == 0 {
		h.logger.Warn("Appointment not found or doesn't belong to organization",
			zap.String("appointment_id", appointmentID),
			zap.String("org_id", orgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment ID or appointment does not belong to organization"})
	}

	h.logger.Info("Successfully validated appointment",
		zap.String("appointment_id", appointmentID),
		zap.String("org_id", orgID))

	return nil
}

// Fixed CreateDiagnosis function
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
	existingDiagnosisID, exists, err := h.checkExistingDiagnosisWithID(c.Context(), diagnosisRequest.AppointmentID, diagnosisRequest.OrgID)
	if err != nil {
		h.logger.Error("failed to check existing diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	// Prepare JSON fields - FIX: Handle medications properly
	var symptomsJSON, medicationsJSON, testResultsJSON, attachmentsJSON []byte
	if len(diagnosisRequest.Symptoms) > 0 {
		symptomsJSON, _ = json.Marshal(diagnosisRequest.Symptoms)
	}

	// FIX: Check for medications directly in request, not nested in TreatmentPlan
	if len(diagnosisRequest.Medications) > 0 {
		medicationsJSON, _ = json.Marshal(diagnosisRequest.Medications)
	} else if diagnosisRequest.TreatmentPlan != nil && len(diagnosisRequest.TreatmentPlan.Medications) > 0 {
		// Fallback to TreatmentPlan if medications are nested there
		medicationsJSON, _ = json.Marshal(diagnosisRequest.TreatmentPlan.Medications)
	}

	if len(diagnosisRequest.TestResults) > 0 {
		testResultsJSON, _ = json.Marshal(diagnosisRequest.TestResults)
	}
	if len(diagnosisRequest.Attachments) > 0 {
		attachmentsJSON, _ = json.Marshal(diagnosisRequest.Attachments)
	}

	// Get procedures and recommendations from treatment plan OR direct fields
	var procedures []string
	var recommendations *string

	// Check if procedures/recommendations are in TreatmentPlan or direct fields
	if diagnosisRequest.TreatmentPlan != nil {
		procedures = diagnosisRequest.TreatmentPlan.Procedures
		recommendations = diagnosisRequest.TreatmentPlan.Recommendations
	} else {
		// If not in TreatmentPlan, check direct fields
		procedures = diagnosisRequest.Procedures
		if diagnosisRequest.Recommendations != "" {
			recommendations = &diagnosisRequest.Recommendations
		}
	}

	var diagnosisID string
	var createdAt, updatedAt time.Time
	var isUpdate bool

	if exists {
		// Update existing diagnosis
		isUpdate = true
		updateQuery := `
			UPDATE medical_diagnoses SET
				patient_id = $2,
				doctor_id = $3,
				org_id = $4,
				patient_name = $5,
				patient_age = $6,
				patient_gender = $7,
				doctor_name = $8,
				doctor_specialty = $9,
				temperature = $10,
				blood_pressure = $11,
				heart_rate = $12,
				weight = $13,
				height = $14,
				bmi = $15,
				chief_complaint = $16,
				symptoms = $17,
				physical_exam = $18,
				primary_diagnosis = $19,
				secondary_diagnoses = $20,
				icd_codes = $21,
				medications = $22,
				procedures = $23,
				recommendations = $24,
				lab_orders = $25,
				test_results = $26,
				specialty = $27,
				specialty_data = $28,
				follow_up_date = $29,
				follow_up_notes = $30,
				referrals = $31,
				status = $32,
				clinical_notes = $33,
				attachments = $34,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
			RETURNING id, created_at, updated_at`

		err = h.pgPool.QueryRow(c.Context(), updateQuery,
			existingDiagnosisID,
			diagnosisRequest.PatientID,
			diagnosisRequest.DoctorID,
			diagnosisRequest.OrgID,
			diagnosisRequest.PatientName,
			diagnosisRequest.PatientAge,
			diagnosisRequest.PatientGender,
			diagnosisRequest.DoctorName,
			diagnosisRequest.DoctorSpecialty,
			// FIX: Access vitals directly from diagnosisRequest, not nested Vitals struct
			diagnosisRequest.Temperature,
			diagnosisRequest.BloodPressure,
			diagnosisRequest.HeartRate,
			diagnosisRequest.Weight,
			diagnosisRequest.Height,
			diagnosisRequest.BMI,
			diagnosisRequest.ChiefComplaint,
			symptomsJSON,
			diagnosisRequest.PhysicalExam,
			diagnosisRequest.PrimaryDiagnosis,
			pq.Array(diagnosisRequest.SecondaryDiagnoses),
			pq.Array(diagnosisRequest.ICDCodes),
			medicationsJSON,
			pq.Array(procedures),
			recommendations,
			pq.Array(diagnosisRequest.LabOrders),
			testResultsJSON,
			diagnosisRequest.Specialty,
			diagnosisRequest.SpecialtyData,
			diagnosisRequest.FollowUpDate,
			diagnosisRequest.FollowUpNotes,
			pq.Array(diagnosisRequest.Referrals),
			diagnosisRequest.Status,
			diagnosisRequest.ClinicalNotes,
			attachmentsJSON,
		).Scan(&diagnosisID, &createdAt, &updatedAt)

		if err != nil {
			h.logger.Error("failed to update diagnosis", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update diagnosis"})
		}

		h.logger.Info("diagnosis updated successfully",
			zap.String("diagnosis_id", diagnosisID),
			zap.String("appointment_id", diagnosisRequest.AppointmentID))
	} else {
		// Create new diagnosis - FIX: Use consistent array handling
		insertQuery := `
			INSERT INTO medical_diagnoses (
				appointment_id, patient_id, doctor_id, org_id, patient_name, patient_age, 
				patient_gender, doctor_name, doctor_specialty, temperature, blood_pressure, 
				heart_rate, weight, height, bmi, chief_complaint, symptoms, physical_exam, 
				primary_diagnosis, secondary_diagnoses, icd_codes, medications, procedures, 
				recommendations, lab_orders, test_results, specialty, specialty_data, 
				follow_up_date, follow_up_notes, referrals, status, clinical_notes, attachments
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, 
				$18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34
			) RETURNING id, created_at`

		err = h.pgPool.QueryRow(c.Context(), insertQuery,
			diagnosisRequest.AppointmentID,
			diagnosisRequest.PatientID,
			diagnosisRequest.DoctorID,
			diagnosisRequest.OrgID,
			diagnosisRequest.PatientName,
			diagnosisRequest.PatientAge,
			diagnosisRequest.PatientGender,
			diagnosisRequest.DoctorName,
			diagnosisRequest.DoctorSpecialty,
			// FIX: Access vitals directly from diagnosisRequest, not nested Vitals struct
			diagnosisRequest.Temperature,
			diagnosisRequest.BloodPressure,
			diagnosisRequest.HeartRate,
			diagnosisRequest.Weight,
			diagnosisRequest.Height,
			diagnosisRequest.BMI,
			diagnosisRequest.ChiefComplaint,
			symptomsJSON,
			diagnosisRequest.PhysicalExam,
			diagnosisRequest.PrimaryDiagnosis,
			pq.Array(diagnosisRequest.SecondaryDiagnoses), // FIX: Use pq.Array consistently
			pq.Array(diagnosisRequest.ICDCodes),           // FIX: Use pq.Array consistently
			medicationsJSON,
			pq.Array(procedures),
			recommendations,
			pq.Array(diagnosisRequest.LabOrders), // FIX: Use pq.Array consistently
			testResultsJSON,
			diagnosisRequest.Specialty,
			diagnosisRequest.SpecialtyData,
			diagnosisRequest.FollowUpDate,
			diagnosisRequest.FollowUpNotes,
			pq.Array(diagnosisRequest.Referrals), // FIX: Use pq.Array consistently
			diagnosisRequest.Status,
			diagnosisRequest.ClinicalNotes,
			attachmentsJSON,
		).Scan(&diagnosisID, &createdAt)

		if err != nil {
			h.logger.Error("failed to insert diagnosis", zap.Error(err))
			if strings.Contains(err.Error(), "duplicate key") {
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Diagnosis with this appointment already exists"})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create diagnosis"})
		}

		updatedAt = createdAt // For new records, updated_at equals created_at
		h.logger.Info("diagnosis created successfully",
			zap.String("diagnosis_id", diagnosisID),
			zap.String("appointment_id", diagnosisRequest.AppointmentID))
	}

	// Prepare response
	response := fiber.Map{
		"diagnosis_id": diagnosisID,
		"created_at":   createdAt,
		"updated_at":   updatedAt,
		"status":       diagnosisRequest.Status,
	}

	if isUpdate {
		response["message"] = "Diagnosis updated successfully"
		return c.Status(fiber.StatusOK).JSON(response)
	} else {
		response["message"] = "Diagnosis created successfully"
		return c.Status(fiber.StatusCreated).JSON(response)
	}
}

// Helper function to check existing diagnosis and return its ID
func (h *DiagnosisHandler) checkExistingDiagnosisWithID(ctx context.Context, appointmentID, orgID string) (string, bool, error) {
	var diagnosisID string
	query := `SELECT id FROM medical_diagnoses WHERE appointment_id = $1 AND org_id = $2`

	err := h.pgPool.QueryRow(ctx, query, appointmentID, orgID).Scan(&diagnosisID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", false, nil // No existing diagnosis found
		}
		return "", false, err // Database error
	}

	return diagnosisID, true, nil // Existing diagnosis found
}

// MedicalDiagnosis represents the medical diagnosis data structure
type MedicalDiagnosis struct {
	ID                 string   `json:"_id,omitempty" bson:"_id,omitempty"`
	Condition          string   `json:"condition" bson:"condition"`
	Specialization     string   `json:"specialization" bson:"specialization"`
	Category           string   `json:"category" bson:"category"`
	ICD                ICDCode  `json:"icd" bson:"icd"`
	Synonyms           []string `json:"synonyms,omitempty" bson:"synonyms,omitempty"`
	CommonPresentation string   `json:"commonPresentation" bson:"commonPresentation"`
	Severity           string   `json:"severity" bson:"severity"`
	Prevalence         string   `json:"prevalence" bson:"prevalence"`
	AgeGroup           []string `json:"ageGroup" bson:"ageGroup"`
	SearchKeywords     []string `json:"searchKeywords,omitempty" bson:"searchKeywords,omitempty"`
}

// ICDCode represents the ICD code structure
type ICDCode struct {
	Code        string `json:"code" bson:"code"`
	Version     string `json:"version" bson:"version"`
	Description string `json:"description" bson:"description"`
}

// DiagnosisSearchParams represents search parameters
type DiagnosisSearchParams struct {
	Term           string   `json:"term"`
	ICDCode        string   `json:"icd_code"`
	Specialization string   `json:"specialization"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	Prevalence     string   `json:"prevalence"`
	AgeGroups      []string `json:"age_groups"`
	Limit          int      `json:"limit"`
	Offset         int      `json:"offset"`
}

// GetDiagnosis retrieves diagnosis by appointment_id from URL path
func (h *DiagnosisHandler) GetDiagnosis(c *fiber.Ctx) error {
	// Get appointment_id from URL path parameters
	// Changed from "appointment_id" to "id" to match the route parameter
	appointmentID := c.Params("id")

	// Debug logging
	fmt.Printf("Path appointment_id: '%s'\n", appointmentID)

	// Check if appointment_id is provided
	if appointmentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "appointment_id parameter is required",
			"details": "Please provide appointment_id in the URL path",
		})
	}

	// Validate appointment_id format (assuming UUID)
	if !validateUUID(appointmentID) {
		h.logger.Warn("invalid appointment ID format", zap.String("appointment_id", appointmentID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Appointment ID must be in UUID format"})
	}

	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
	}

	fmt.Println("Auth ID:", authID)

	// Query to get all diagnoses for the appointment
	query := `
		SELECT
			id, appointment_id, patient_id, doctor_id, org_id, patient_name, patient_age,
			patient_gender, doctor_name, doctor_specialty, temperature, blood_pressure,
			heart_rate, weight, height, bmi, chief_complaint, symptoms, physical_exam,
			primary_diagnosis, secondary_diagnoses, icd_codes, medications, procedures,
			recommendations, lab_orders, test_results, specialty, specialty_data,
			follow_up_date, follow_up_notes, referrals, status, clinical_notes,
			attachments, created_at, updated_at
		FROM medical_diagnoses
		WHERE appointment_id = $1
		ORDER BY created_at DESC`

	rows, err := h.pgPool.Query(c.Context(), query, appointmentID)
	if err != nil {
		h.logger.Error("failed to retrieve diagnoses", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve diagnoses"})
	}
	defer rows.Close()

	var diagnoses []DiagnosisResponse

	for rows.Next() {
		var diagnosis DiagnosisResponse
		var symptomsJSON, medicationsJSON, testResultsJSON, attachmentsJSON []byte

		err := rows.Scan(
			&diagnosis.ID,
			&diagnosis.AppointmentID,
			&diagnosis.PatientID,
			&diagnosis.DoctorID,
			&diagnosis.OrgID,
			&diagnosis.PatientName,
			&diagnosis.PatientAge,
			&diagnosis.PatientGender,
			&diagnosis.DoctorName,
			&diagnosis.DoctorSpecialty,
			&diagnosis.Vitals.Temperature,
			&diagnosis.Vitals.BloodPressure,
			&diagnosis.Vitals.HeartRate,
			&diagnosis.Vitals.Weight,
			&diagnosis.Vitals.Height,
			&diagnosis.Vitals.BMI,
			&diagnosis.ChiefComplaint,
			&symptomsJSON,
			&diagnosis.PhysicalExam,
			&diagnosis.PrimaryDiagnosis,
			&diagnosis.SecondaryDiagnoses,
			&diagnosis.ICDCodes,
			&medicationsJSON,
			&diagnosis.TreatmentPlan.Procedures,
			&diagnosis.TreatmentPlan.Recommendations,
			&diagnosis.LabOrders,
			&testResultsJSON,
			&diagnosis.Specialty,
			&diagnosis.SpecialtyData,
			&diagnosis.FollowUpDate,
			&diagnosis.FollowUpNotes,
			&diagnosis.Referrals,
			&diagnosis.Status,
			&diagnosis.ClinicalNotes,
			&attachmentsJSON,
			&diagnosis.CreatedAt,
			&diagnosis.UpdatedAt,
		)

		if err != nil {
			h.logger.Error("failed to scan diagnosis row", zap.Error(err))
			continue
		}

		// Parse JSON fields
		if symptomsJSON != nil {
			json.Unmarshal(symptomsJSON, &diagnosis.Symptoms)
		}
		if medicationsJSON != nil {
			json.Unmarshal(medicationsJSON, &diagnosis.TreatmentPlan.Medications)
		}
		if testResultsJSON != nil {
			json.Unmarshal(testResultsJSON, &diagnosis.TestResults)
		}
		if attachmentsJSON != nil {
			json.Unmarshal(attachmentsJSON, &diagnosis.Attachments)
		}

		diagnoses = append(diagnoses, diagnosis)
	}

	if err := rows.Err(); err != nil {
		h.logger.Error("error iterating over diagnosis rows", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve diagnoses"})
	}

	// Check if no diagnoses found
	if len(diagnoses) == 0 {
		h.logger.Info("no diagnoses found for appointment", zap.String("appointment_id", appointmentID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "No diagnosis found",
			"message": "No diagnosis found for the specified appointment",
		})
	}

	// Return the first (most recent) diagnosis in the format expected by frontend
	// Frontend expects { diagnosis: {...} } not { diagnoses: [...] }
	latestDiagnosis := diagnoses[0]

	h.logger.Info("diagnosis retrieved successfully",
		zap.String("appointment_id", appointmentID),
		zap.String("diagnosis_id", latestDiagnosis.ID))

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":   "Diagnosis retrieved successfully",
		"diagnosis": latestDiagnosis, // Changed from "diagnoses" to "diagnosis"
		"count":     len(diagnoses),  // Still include count for debugging
	})
}

// GetMedicalHistory retrieves comprehensive medical history for a patient
func (h *DiagnosisHandler) GetMedicalHistory(c *fiber.Ctx) error {
	patientID := c.Params("id")
	if patientID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Patient ID is required"})
	}

	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
	}
	h.logger.Debug("Auth ID", zap.String("authID", authID))

	// Get query parameters for filtering
	orgID := c.Query("org_id")
	limit := c.QueryInt("limit", 50) // Default to 50 records
	offset := c.QueryInt("offset", 0)
	status := c.Query("status", "finalized") // Default to finalized diagnoses

	// Build query with filters
	baseQuery := `
			SELECT 
				id, appointment_id, doctor_name, doctor_specialty, temperature, blood_pressure, 
				heart_rate, weight, height, bmi, chief_complaint, symptoms, physical_exam, 
				primary_diagnosis, secondary_diagnoses, icd_codes, medications, procedures, 
				recommendations, lab_orders, test_results, specialty, specialty_data, 
				follow_up_date, follow_up_notes, referrals, status, clinical_notes, 
				attachments, created_at, updated_at
			FROM medical_diagnoses 
			WHERE patient_id = $1`

	args := []interface{}{patientID}
	argCount := 2

	// Add org filter if provided
	if orgID != "" {
		baseQuery += fmt.Sprintf(" AND org_id = $%d", argCount)
		args = append(args, orgID)
		argCount++
	}

	// Add status filter
	if status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argCount)
		args = append(args, status)
		argCount++
	}

	// Order by created_at descending and add pagination
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argCount, argCount+1)
	args = append(args, limit, offset)

	h.logger.Debug("executing medical history query", zap.String("query", baseQuery))

	rows, err := h.pgPool.Query(c.Context(), baseQuery, args...)
	if err != nil {
		h.logger.Error("failed to retrieve medical history", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve medical history"})
	}
	defer rows.Close()

	var medicalHistory []MedicalHistoryRecord
	var patientInfo PatientSummary

	for rows.Next() {
		var record MedicalHistoryRecord
		var symptomsJSON, medicationsJSON, testResultsJSON, attachmentsJSON []byte

		err := rows.Scan(
			&record.ID,
			&record.AppointmentID,
			&record.DoctorName,
			&record.DoctorSpecialty,
			&record.Vitals.Temperature,
			&record.Vitals.BloodPressure,
			&record.Vitals.HeartRate,
			&record.Vitals.Weight,
			&record.Vitals.Height,
			&record.Vitals.BMI,
			&record.ChiefComplaint,
			&symptomsJSON,
			&record.PhysicalExam,
			&record.PrimaryDiagnosis,
			&record.SecondaryDiagnoses,
			&record.ICDCodes,
			&medicationsJSON,
			&record.TreatmentPlan.Procedures,
			&record.TreatmentPlan.Recommendations,
			&record.LabOrders,
			&testResultsJSON,
			&record.Specialty,
			&record.SpecialtyData,
			&record.FollowUpDate,
			&record.FollowUpNotes,
			&record.Referrals,
			&record.Status,
			&record.ClinicalNotes,
			&attachmentsJSON,
			&record.CreatedAt,
			&record.UpdatedAt,
		)

		if err != nil {
			h.logger.Error("failed to scan medical history record", zap.Error(err))
			continue
		}

		// Parse JSON fields
		if symptomsJSON != nil {
			json.Unmarshal(symptomsJSON, &record.Symptoms)
		}
		if medicationsJSON != nil {
			json.Unmarshal(medicationsJSON, &record.TreatmentPlan.Medications)
		}
		if testResultsJSON != nil {
			json.Unmarshal(testResultsJSON, &record.TestResults)
		}
		if attachmentsJSON != nil {
			json.Unmarshal(attachmentsJSON, &record.Attachments)
		}

		medicalHistory = append(medicalHistory, record)
	}

	// Get patient summary information from the first record or a separate query
	if len(medicalHistory) > 0 {
		// Get patient basic info from the most recent record
		patientQuery := `
				SELECT DISTINCT patient_name, patient_age, patient_gender
				FROM medical_diagnoses 
				WHERE patient_id = $1 
				ORDER BY created_at DESC 
				LIMIT 1`

		err = h.pgPool.QueryRow(c.Context(), patientQuery, patientID).Scan(
			&patientInfo.PatientName,
			&patientInfo.PatientAge,
			&patientInfo.PatientGender,
		)

		if err != nil && err != pgx.ErrNoRows {
			h.logger.Error("failed to get patient info", zap.Error(err))
		}
	}

	// Get summary statistics
	summary := h.generateMedicalSummary(medicalHistory)

	h.logger.Info("medical history retrieved successfully",
		zap.String("patient_id", patientID),
		zap.Int("record_count", len(medicalHistory)))

	response := fiber.Map{
		"message": "Medical history retrieved successfully",
		"patient_info": fiber.Map{
			"patient_id":     patientID,
			"patient_name":   patientInfo.PatientName,
			"patient_age":    patientInfo.PatientAge,
			"patient_gender": patientInfo.PatientGender,
		},
		"summary": summary,
		"records": medicalHistory,
		"pagination": fiber.Map{
			"limit":        limit,
			"offset":       offset,
			"record_count": len(medicalHistory),
		},
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// Helper function to generate medical summary
func (h *DiagnosisHandler) generateMedicalSummary(records []MedicalHistoryRecord) MedicalSummary {
	summary := MedicalSummary{
		TotalVisits: len(records),
		Diagnoses:   make(map[string]int),
		Medications: make(map[string]int),
		Allergies:   []string{},
	}

	if len(records) == 0 {
		return summary
	}

	// Get date range
	if len(records) > 0 {
		summary.FirstVisit = &records[len(records)-1].CreatedAt
		summary.LastVisit = &records[0].CreatedAt
	}

	// Aggregate diagnoses and medications
	for _, record := range records {
		// Count primary diagnoses
		if record.PrimaryDiagnosis != "" {
			summary.Diagnoses[record.PrimaryDiagnosis]++
		}

		// Count secondary diagnoses
		for _, diagnosis := range record.SecondaryDiagnoses {
			summary.Diagnoses[diagnosis]++
		}

		// Count medications
		for _, medication := range record.TreatmentPlan.Medications {
			if medication.Name != "" {
				summary.Medications[medication.Name]++
			}
		}

		// Collect chronic conditions (appearing in multiple visits)
		// This is a simplified approach - you might want more sophisticated logic
	}

	// Identify chronic conditions (diagnoses appearing multiple times)
	for diagnosis, count := range summary.Diagnoses {
		if count >= 2 { // Appeared in 2 or more visits
			summary.ChronicConditions = append(summary.ChronicConditions, diagnosis)
		}
	}

	return summary
}

// Supporting structs for the response
type DiagnosisResponse struct {
	ID                 string         `json:"id"`
	AppointmentID      string         `json:"appointment_id"`
	PatientID          string         `json:"patient_id"`
	DoctorID           string         `json:"doctor_id"`
	OrgID              string         `json:"org_id"`
	PatientName        *string        `json:"patient_name"`
	PatientAge         *int           `json:"patient_age"`
	PatientGender      *string        `json:"patient_gender"`
	DoctorName         *string        `json:"doctor_name"`
	DoctorSpecialty    *string        `json:"doctor_specialty"`
	Vitals             VitalsResponse `json:"vitals"`
	ChiefComplaint     *string        `json:"chief_complaint"`
	Symptoms           []Symptom      `json:"symptoms"`
	PhysicalExam       *string        `json:"physical_exam"`
	PrimaryDiagnosis   string         `json:"primary_diagnosis"`
	SecondaryDiagnoses []string       `json:"secondary_diagnoses"`
	ICDCodes           []string       `json:"icd_codes"`
	TreatmentPlan      TreatmentPlan  `json:"treatment_plan"`
	LabOrders          []string       `json:"lab_orders"`
	TestResults        []TestResult   `json:"test_results"`
	Specialty          *string        `json:"specialty"`
	SpecialtyData      interface{}    `json:"specialty_data"`
	FollowUpDate       *time.Time     `json:"follow_up_date"`
	FollowUpNotes      *string        `json:"follow_up_notes"`
	Referrals          []string       `json:"referrals"`
	Status             string         `json:"status"`
	ClinicalNotes      *string        `json:"clinical_notes"`
	Attachments        []Attachment   `json:"attachments"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type VitalsResponse struct {
	Temperature   *float64 `json:"temperature"`
	BloodPressure *string  `json:"blood_pressure"`
	HeartRate     *int     `json:"heart_rate"`
	Weight        *float64 `json:"weight"`
	Height        *float64 `json:"height"`
	BMI           *float64 `json:"bmi"`
}

type MedicalHistoryRecord struct {
	ID                 string         `json:"id"`
	AppointmentID      string         `json:"appointment_id"`
	DoctorName         *string        `json:"doctor_name"`
	DoctorSpecialty    *string        `json:"doctor_specialty"`
	Vitals             VitalsResponse `json:"vitals"`
	ChiefComplaint     *string        `json:"chief_complaint"`
	Symptoms           []Symptom      `json:"symptoms"`
	PhysicalExam       *string        `json:"physical_exam"`
	PrimaryDiagnosis   string         `json:"primary_diagnosis"`
	SecondaryDiagnoses []string       `json:"secondary_diagnoses"`
	ICDCodes           []string       `json:"icd_codes"`
	TreatmentPlan      TreatmentPlan  `json:"treatment_plan"`
	LabOrders          []string       `json:"lab_orders"`
	TestResults        []TestResult   `json:"test_results"`
	Specialty          *string        `json:"specialty"`
	SpecialtyData      interface{}    `json:"specialty_data"`
	FollowUpDate       *time.Time     `json:"follow_up_date"`
	FollowUpNotes      *string        `json:"follow_up_notes"`
	Referrals          []string       `json:"referrals"`
	Status             string         `json:"status"`
	ClinicalNotes      *string        `json:"clinical_notes"`
	Attachments        []Attachment   `json:"attachments"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type PatientSummary struct {
	PatientName   *string `json:"patient_name"`
	PatientAge    *int    `json:"patient_age"`
	PatientGender *string `json:"patient_gender"`
}

type MedicalSummary struct {
	TotalVisits       int            `json:"total_visits"`
	FirstVisit        *time.Time     `json:"first_visit"`
	LastVisit         *time.Time     `json:"last_visit"`
	ChronicConditions []string       `json:"chronic_conditions"`
	Diagnoses         map[string]int `json:"diagnoses"`
	Medications       map[string]int `json:"medications"`
	Allergies         []string       `json:"allergies"`
}

// You'll need these supporting structs if they don't exist
type Symptom struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Duration    string `json:"duration"`
	Description string `json:"description"`
}

type Medication struct {
	Name         string `json:"name"`
	Dosage       string `json:"dosage"`
	Frequency    string `json:"frequency"`
	Duration     string `json:"duration"`
	Instructions string `json:"instructions"`
}

type TreatmentPlan struct {
	Medications     []Medication `json:"medications"`
	Procedures      []string     `json:"procedures"`
	Recommendations *string      `json:"recommendations"`
}

type TestResult struct {
	TestName string    `json:"test_name"`
	Result   string    `json:"result"`
	Date     time.Time `json:"date"`
	Notes    string    `json:"notes"`
}

type Attachment struct {
	FileName string `json:"file_name"`
	FileType string `json:"file_type"`
	FileSize int64  `json:"file_size"`
	URL      string `json:"url"`
}
