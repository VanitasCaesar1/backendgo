package handlers

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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

type Treatment struct {
	Medications     []Medication `json:"medications"`
	Procedures      []string     `json:"procedures"`
	Recommendations *string      `json:"recommendations"`
}

type DiagnosisRequest struct {
	AppointmentID   string           `json:"appointment_id" validate:"required,uuid"`
	PatientID       string           `json:"patient_id" validate:"required"`
	DoctorID        string           `json:"doctor_id" validate:"required,uuid"`
	OrgID           string           `json:"org_id" validate:"required"`
	PatientName     *string          `json:"patient_name,omitempty"`
	PatientAge      *int             `json:"patient_age,omitempty"`
	PatientGender   *string          `json:"patient_gender,omitempty" validate:"omitempty,oneof=male female other"`
	DoctorName      *string          `json:"doctor_name,omitempty"`
	DoctorSpecialty *string          `json:"doctor_specialty,omitempty"`
	Specializations *json.RawMessage `json:"specializations,omitempty"`

	// Vitals as strings to match frontend input
	Temperature      string `json:"temperature"`
	BloodPressure    string `json:"blood_pressure"`
	HeartRate        string `json:"heart_rate"`
	Weight           string `json:"weight"`
	Height           string `json:"height"`
	BMI              string `json:"bmi"`
	RespiratoryRate  string `json:"respiratory_rate"`
	OxygenSaturation string `json:"oxygen_saturation"`

	// Main complaint and symptoms
	ChiefComplaint   *string   `json:"chief_complaint,omitempty"`
	PrimaryComplaint *string   `json:"primary_complaint,omitempty"` // New field
	Symptoms         []Symptom `json:"symptoms"`

	// New symptom-related fields
	SymptomTimeline          *json.RawMessage `json:"symptom_timeline,omitempty"`
	SymptomSummary           *json.RawMessage `json:"symptom_summary,omitempty"`
	SymptomCategories        []string         `json:"symptom_categories,omitempty"`
	SymptomTriggers          *json.RawMessage `json:"symptom_triggers,omitempty"`
	SymptomRelievingFactors  *json.RawMessage `json:"symptom_relieving_factors,omitempty"`
	SymptomQualityDetails    *json.RawMessage `json:"symptom_quality_details,omitempty"`
	SymptomProgression       *json.RawMessage `json:"symptom_progression,omitempty"`
	SymptomRadiationPatterns *json.RawMessage `json:"symptom_radiation_patterns,omitempty"`

	PhysicalExam       *string          `json:"physical_exam,omitempty"`
	PrimaryDiagnosis   string           `json:"primary_diagnosis"`
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

	// Validate vitals ranges (now handling string fields)
	if req.Temperature != "" {
		temp, err := strconv.ParseFloat(req.Temperature, 64)
		if err != nil {
			return errors.New("invalid temperature format")
		}
		if temp < 20.0 || temp > 50.0 {
			return errors.New("temperature must be between 20.0 and 50.0 degrees Celsius")
		}
	}

	if req.HeartRate != "" {
		hr, err := strconv.Atoi(req.HeartRate)
		if err != nil {
			return errors.New("invalid heart rate format")
		}
		if hr < 30 || hr > 250 {
			return errors.New("heart rate must be between 30 and 250 bpm")
		}
	}

	if req.BMI != "" {
		bmi, err := strconv.ParseFloat(req.BMI, 64)
		if err != nil {
			return errors.New("invalid BMI format")
		}
		if bmi < 10.0 || bmi > 60.0 {
			return errors.New("BMI must be between 10.0 and 60.0")
		}
	}

	// Additional validations for other vitals
	if req.Weight != "" {
		weight, err := strconv.ParseFloat(req.Weight, 64)
		if err != nil {
			return errors.New("invalid weight format")
		}
		if weight < 0.5 || weight > 1000.0 {
			return errors.New("weight must be between 0.5 and 1000.0 kg")
		}
	}

	if req.Height != "" {
		height, err := strconv.ParseFloat(req.Height, 64)
		if err != nil {
			return errors.New("invalid height format")
		}
		if height < 30.0 || height > 300.0 {
			return errors.New("height must be between 30.0 and 300.0 cm")
		}
	}

	if req.RespiratoryRate != "" {
		rr, err := strconv.Atoi(req.RespiratoryRate)
		if err != nil {
			return errors.New("invalid respiratory rate format")
		}
		if rr < 5 || rr > 60 {
			return errors.New("respiratory rate must be between 5 and 60 breaths per minute")
		}
	}

	if req.OxygenSaturation != "" {
		os, err := strconv.ParseFloat(req.OxygenSaturation, 64)
		if err != nil {
			return errors.New("invalid oxygen saturation format")
		}
		if os < 70.0 || os > 100.0 {
			return errors.New("oxygen saturation must be between 70.0 and 100.0 percent")
		}
	}

	// Validate blood pressure format (e.g., "120/80")
	if req.BloodPressure != "" {
		parts := strings.Split(req.BloodPressure, "/")
		if len(parts) != 2 {
			return errors.New("blood pressure must be in format 'systolic/diastolic' (e.g., '120/80')")
		}

		systolic, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return errors.New("invalid systolic blood pressure format")
		}

		diastolic, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return errors.New("invalid diastolic blood pressure format")
		}

		if systolic < 70 || systolic > 250 {
			return errors.New("systolic blood pressure must be between 70 and 250 mmHg")
		}

		if diastolic < 40 || diastolic > 150 {
			return errors.New("diastolic blood pressure must be between 40 and 150 mmHg")
		}

		if systolic <= diastolic {
			return errors.New("systolic blood pressure must be greater than diastolic")
		}
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

// Helper function to safely convert string to float64 pointer
func stringToFloat64Ptr(s string) *float64 {
	if s == "" {
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return &f
	}
	return nil
}

// Helper function to safely convert string to int pointer
func stringToIntPtr(s string) *int {
	if s == "" {
		return nil
	}
	if i, err := strconv.Atoi(s); err == nil {
		return &i
	}
	return nil
}

func (h *DiagnosisHandler) CreateDiagnosis(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
	}
	h.logger.Debug("Auth ID", zap.String("authID", authID))

	// Log raw request body for debugging
	rawBody := c.Body()
	h.logger.Debug("raw request body", zap.String("body", string(rawBody)))

	// Parse diagnosis data from request body
	var diagnosisRequest DiagnosisRequest
	if err := c.BodyParser(&diagnosisRequest); err != nil {
		h.logger.Error("failed to parse diagnosis data",
			zap.Error(err),
			zap.String("raw_body", string(rawBody)))

		// Check if symptoms field is a string instead of array
		var rawRequest map[string]interface{}
		if jsonErr := json.Unmarshal(rawBody, &rawRequest); jsonErr == nil {
			if symptoms, exists := rawRequest["symptoms"]; exists {
				h.logger.Error("symptoms field type mismatch",
					zap.Any("symptoms_type", fmt.Sprintf("%T", symptoms)),
					zap.Any("symptoms_value", symptoms))
			}
		}

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
	}

	// Log the parsed request for debugging INCLUDING clinical_notes
	h.logger.Debug("parsed diagnosis request",
		zap.String("appointment_id", diagnosisRequest.AppointmentID),
		zap.String("patient_id", diagnosisRequest.PatientID),
		zap.String("doctor_id", diagnosisRequest.DoctorID),
		zap.String("org_id", diagnosisRequest.OrgID),
		zap.String("status", diagnosisRequest.Status),
		zap.Int("symptoms_count", len(diagnosisRequest.Symptoms)),
		zap.Any("clinical_notes", diagnosisRequest.ClinicalNotes),
		zap.Any("specializations", diagnosisRequest.Specializations))

	// Additional custom validations
	if err := h.validateDiagnosisRequest(&diagnosisRequest); err != nil {
		h.logger.Error("custom validation failed", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Convert string vitals to proper database types with better validation
	temperature := stringToFloat64Ptr(diagnosisRequest.Temperature)
	heartRate := stringToIntPtr(diagnosisRequest.HeartRate)
	weight := stringToFloat64Ptr(diagnosisRequest.Weight)
	height := stringToFloat64Ptr(diagnosisRequest.Height)
	bmi := stringToFloat64Ptr(diagnosisRequest.BMI)
	respiratoryRate := stringToIntPtr(diagnosisRequest.RespiratoryRate)
	oxygenSaturation := stringToIntPtr(diagnosisRequest.OxygenSaturation)

	// Log vital signs conversion for debugging
	h.logger.Debug("vital signs converted",
		zap.Any("temperature", temperature),
		zap.Any("heart_rate", heartRate),
		zap.Any("weight", weight),
		zap.Any("height", height),
		zap.Any("bmi", bmi))

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

	// Prepare JSON fields with better error handling
	var symptomsJSON, medicationsJSON, testResultsJSON, attachmentsJSON []byte
	var symptomTimelineJSON, symptomSummaryJSON, symptomTriggersJSON []byte
	var symptomRelievingFactorsJSON, symptomQualityDetailsJSON []byte
	var symptomProgressionJSON, symptomRadiationPatternsJSON []byte
	var specialtyDataJSON, specializationsJSON []byte

	// Handle symptoms - ensure we always have valid JSON
	if len(diagnosisRequest.Symptoms) > 0 {
		symptomsJSON, err = json.Marshal(diagnosisRequest.Symptoms)
		if err != nil {
			h.logger.Error("failed to marshal symptoms", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid symptoms data"})
		}
		h.logger.Debug("symptoms marshaled successfully", zap.String("json", string(symptomsJSON)))
	} else {
		symptomsJSON = []byte("[]") // Default to empty array
		h.logger.Debug("using empty symptoms array")
	}

	// Handle medications from request or TreatmentPlan
	if len(diagnosisRequest.Medications) > 0 {
		medicationsJSON, err = json.Marshal(diagnosisRequest.Medications)
		if err != nil {
			h.logger.Error("failed to marshal medications", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid medications data"})
		}
	} else if diagnosisRequest.TreatmentPlan != nil && len(diagnosisRequest.TreatmentPlan.Medications) > 0 {
		medicationsJSON, err = json.Marshal(diagnosisRequest.TreatmentPlan.Medications)
		if err != nil {
			h.logger.Error("failed to marshal treatment plan medications", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid treatment plan medications data"})
		}
	} else {
		medicationsJSON = []byte("[]") // Default to empty array
	}

	// Handle test results
	if len(diagnosisRequest.TestResults) > 0 {
		testResultsJSON, err = json.Marshal(diagnosisRequest.TestResults)
		if err != nil {
			h.logger.Error("failed to marshal test results", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid test results data"})
		}
	} else {
		testResultsJSON = []byte("[]") // Default to empty array
	}

	// Handle attachments
	if len(diagnosisRequest.Attachments) > 0 {
		attachmentsJSON, err = json.Marshal(diagnosisRequest.Attachments)
		if err != nil {
			h.logger.Error("failed to marshal attachments", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid attachments data"})
		}
	} else {
		attachmentsJSON = []byte("[]") // Default to empty array
	}

	// Handle symptom-related JSON fields with proper validation
	if diagnosisRequest.SymptomTimeline != nil {
		// Validate JSON
		var temp interface{}
		if err := json.Unmarshal(*diagnosisRequest.SymptomTimeline, &temp); err != nil {
			h.logger.Error("invalid symptom timeline JSON", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid symptom timeline data"})
		}
		symptomTimelineJSON = *diagnosisRequest.SymptomTimeline
	} else {
		symptomTimelineJSON = nil // Use NULL instead of empty JSON
	}

	if diagnosisRequest.SymptomSummary != nil {
		// Validate JSON
		var temp interface{}
		if err := json.Unmarshal(*diagnosisRequest.SymptomSummary, &temp); err != nil {
			h.logger.Error("invalid symptom summary JSON", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid symptom summary data"})
		}
		symptomSummaryJSON = *diagnosisRequest.SymptomSummary
	} else {
		symptomSummaryJSON = nil
	}

	if diagnosisRequest.SymptomTriggers != nil {
		// Validate JSON
		var temp interface{}
		if err := json.Unmarshal(*diagnosisRequest.SymptomTriggers, &temp); err != nil {
			h.logger.Error("invalid symptom triggers JSON", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid symptom triggers data"})
		}
		symptomTriggersJSON = *diagnosisRequest.SymptomTriggers
	} else {
		symptomTriggersJSON = nil
	}

	if diagnosisRequest.SymptomRelievingFactors != nil {
		// Validate JSON
		var temp interface{}
		if err := json.Unmarshal(*diagnosisRequest.SymptomRelievingFactors, &temp); err != nil {
			h.logger.Error("invalid symptom relieving factors JSON", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid symptom relieving factors data"})
		}
		symptomRelievingFactorsJSON = *diagnosisRequest.SymptomRelievingFactors
	} else {
		symptomRelievingFactorsJSON = nil
	}

	if diagnosisRequest.SymptomQualityDetails != nil {
		// Validate JSON
		var temp interface{}
		if err := json.Unmarshal(*diagnosisRequest.SymptomQualityDetails, &temp); err != nil {
			h.logger.Error("invalid symptom quality details JSON", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid symptom quality details data"})
		}
		symptomQualityDetailsJSON = *diagnosisRequest.SymptomQualityDetails
	} else {
		symptomQualityDetailsJSON = nil
	}

	if diagnosisRequest.SymptomProgression != nil {
		// Validate JSON
		var temp interface{}
		if err := json.Unmarshal(*diagnosisRequest.SymptomProgression, &temp); err != nil {
			h.logger.Error("invalid symptom progression JSON", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid symptom progression data"})
		}
		symptomProgressionJSON = *diagnosisRequest.SymptomProgression
	} else {
		symptomProgressionJSON = nil
	}

	if diagnosisRequest.SymptomRadiationPatterns != nil {
		// Validate JSON
		var temp interface{}
		if err := json.Unmarshal(*diagnosisRequest.SymptomRadiationPatterns, &temp); err != nil {
			h.logger.Error("invalid symptom radiation patterns JSON", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid symptom radiation patterns data"})
		}
		symptomRadiationPatternsJSON = *diagnosisRequest.SymptomRadiationPatterns
	} else {
		symptomRadiationPatternsJSON = nil
	}

	// Handle specialty data
	if diagnosisRequest.SpecialtyData != nil {
		// Validate JSON
		var temp interface{}
		if err := json.Unmarshal(*diagnosisRequest.SpecialtyData, &temp); err != nil {
			h.logger.Error("invalid specialty data JSON", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid specialty data"})
		}
		specialtyDataJSON = *diagnosisRequest.SpecialtyData
	} else {
		specialtyDataJSON = nil
	}

	// ✅ FIXED: Handle specializations data
	if diagnosisRequest.Specializations != nil {
		// Validate JSON
		var temp interface{}
		if err := json.Unmarshal(*diagnosisRequest.Specializations, &temp); err != nil {
			h.logger.Error("invalid specializations JSON", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid specializations data"})
		}
		specializationsJSON = *diagnosisRequest.Specializations
		h.logger.Debug("specializations data processed", zap.String("json", string(specializationsJSON)))
	} else {
		specializationsJSON = nil
		h.logger.Debug("no specializations data provided")
	}

	// Add debug logging to see what we're actually inserting
	h.logger.Debug("JSON data being processed",
		zap.String("symptoms", string(symptomsJSON)),
		zap.Bool("symptom_timeline_present", symptomTimelineJSON != nil),
		zap.Bool("symptom_summary_present", symptomSummaryJSON != nil),
		zap.Int("symptom_categories_count", len(diagnosisRequest.SymptomCategories)),
		zap.Any("clinical_notes_value", diagnosisRequest.ClinicalNotes),
		zap.Bool("specializations_present", specializationsJSON != nil))

	// Get procedures and recommendations from treatment plan OR direct fields
	var procedures []string
	var recommendations *string

	if diagnosisRequest.TreatmentPlan != nil {
		procedures = diagnosisRequest.TreatmentPlan.Procedures
		recommendations = diagnosisRequest.TreatmentPlan.Recommendations
	} else {
		procedures = diagnosisRequest.Procedures
		if diagnosisRequest.Recommendations != "" {
			recommendations = &diagnosisRequest.Recommendations
		}
	}

	// Ensure procedures is not nil
	if procedures == nil {
		procedures = []string{}
	}

	var diagnosisID string
	var createdAt, updatedAt time.Time
	var isUpdate bool

	if exists {
		// Update existing diagnosis
		h.logger.Info("updating existing diagnosis", zap.String("diagnosis_id", existingDiagnosisID))

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
				referrals = $29,
				status = $30,
				clinical_notes = $31,
				attachments = $32,
				respiratory_rate = $33,
				oxygen_saturation = $34,
				symptom_timeline = $35,
				symptom_summary = $36,
				primary_complaint = $37,
				symptom_categories = $38,
				symptom_triggers = $39,
				symptom_relieving_factors = $40,
				symptom_quality_details = $41,
				symptom_progression = $42,
				symptom_radiation_patterns = $43,
				specializations = $44,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
			RETURNING id, created_at, updated_at`

		if err = h.pgPool.QueryRow(c.Context(), updateQuery,
			existingDiagnosisID,               // $1
			diagnosisRequest.PatientID,        // $2
			diagnosisRequest.DoctorID,         // $3
			diagnosisRequest.OrgID,            // $4
			diagnosisRequest.PatientName,      // $5
			diagnosisRequest.PatientAge,       // $6
			diagnosisRequest.PatientGender,    // $7
			diagnosisRequest.DoctorName,       // $8
			diagnosisRequest.DoctorSpecialty,  // $9
			temperature,                       // $10
			diagnosisRequest.BloodPressure,    // $11
			heartRate,                         // $12
			weight,                            // $13
			height,                            // $14
			bmi,                               // $15
			diagnosisRequest.ChiefComplaint,   // $16
			symptomsJSON,                      // $17
			diagnosisRequest.PhysicalExam,     // $18
			diagnosisRequest.PrimaryDiagnosis, // $19
			pq.Array(diagnosisRequest.SecondaryDiagnoses), // $20
			pq.Array(diagnosisRequest.ICDCodes),           // $21
			medicationsJSON,                               // $22
			pq.Array(procedures),                          // $23
			recommendations,                               // $24
			pq.Array(diagnosisRequest.LabOrders),          // $25
			testResultsJSON,                               // $26
			diagnosisRequest.Specialty,                    // $27
			specialtyDataJSON,                             // $28
			pq.Array(diagnosisRequest.Referrals),          // $29
			diagnosisRequest.Status,                       // $30
			diagnosisRequest.ClinicalNotes,                // $31
			attachmentsJSON,                               // $32
			respiratoryRate,                               // $33
			oxygenSaturation,                              // $34
			symptomTimelineJSON,                           // $35
			symptomSummaryJSON,                            // $36
			diagnosisRequest.PrimaryComplaint,             // $37
			pq.Array(diagnosisRequest.SymptomCategories),  // $38
			symptomTriggersJSON,                           // $39
			symptomRelievingFactorsJSON,                   // $40
			symptomQualityDetailsJSON,                     // $41
			symptomProgressionJSON,                        // $42
			symptomRadiationPatternsJSON,                  // $43
			specializationsJSON,                           // $44 ✅ ADDED
		).Scan(&diagnosisID, &createdAt, &updatedAt); err != nil {
			h.logger.Error("failed to update diagnosis",
				zap.Error(err),
				zap.String("diagnosis_id", existingDiagnosisID),
				zap.String("appointment_id", diagnosisRequest.AppointmentID))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update diagnosis"})
		}
		isUpdate = true
		h.logger.Info("diagnosis updated successfully",
			zap.String("diagnosis_id", diagnosisID),
			zap.String("appointment_id", diagnosisRequest.AppointmentID))

	} else {
		// Create new diagnosis
		h.logger.Info("creating new diagnosis", zap.String("appointment_id", diagnosisRequest.AppointmentID))

		insertQuery := `
			INSERT INTO medical_diagnoses (
				appointment_id, patient_id, doctor_id, org_id, patient_name, patient_age, 
				patient_gender, doctor_name, doctor_specialty, temperature, blood_pressure, 
				heart_rate, weight, height, bmi, chief_complaint, symptoms, physical_exam, 
				primary_diagnosis, secondary_diagnoses, icd_codes, medications, procedures, 
				recommendations, lab_orders, test_results, specialty, specialty_data, 
				referrals, status, clinical_notes, attachments,
				respiratory_rate, oxygen_saturation, symptom_timeline, symptom_summary, 
				primary_complaint, symptom_categories, symptom_triggers, symptom_relieving_factors,
				symptom_quality_details, symptom_progression, symptom_radiation_patterns, specializations
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, 
				$18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, 
				$33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44
			) RETURNING id, created_at`

		err = h.pgPool.QueryRow(c.Context(), insertQuery,
			diagnosisRequest.AppointmentID,                // $1
			diagnosisRequest.PatientID,                    // $2
			diagnosisRequest.DoctorID,                     // $3
			diagnosisRequest.OrgID,                        // $4
			diagnosisRequest.PatientName,                  // $5
			diagnosisRequest.PatientAge,                   // $6
			diagnosisRequest.PatientGender,                // $7
			diagnosisRequest.DoctorName,                   // $8
			diagnosisRequest.DoctorSpecialty,              // $9
			temperature,                                   // $10
			diagnosisRequest.BloodPressure,                // $11
			heartRate,                                     // $12
			weight,                                        // $13
			height,                                        // $14
			bmi,                                           // $15
			diagnosisRequest.ChiefComplaint,               // $16
			symptomsJSON,                                  // $17
			diagnosisRequest.PhysicalExam,                 // $18
			diagnosisRequest.PrimaryDiagnosis,             // $19
			pq.Array(diagnosisRequest.SecondaryDiagnoses), // $20
			pq.Array(diagnosisRequest.ICDCodes),           // $21
			medicationsJSON,                               // $22
			pq.Array(procedures),                          // $23
			recommendations,                               // $24
			pq.Array(diagnosisRequest.LabOrders),          // $25
			testResultsJSON,                               // $26
			diagnosisRequest.Specialty,                    // $27
			specialtyDataJSON,                             // $28
			pq.Array(diagnosisRequest.Referrals),          // $29
			diagnosisRequest.Status,                       // $30
			diagnosisRequest.ClinicalNotes,                // $31
			attachmentsJSON,                               // $32
			respiratoryRate,                               // $33
			oxygenSaturation,                              // $34
			symptomTimelineJSON,                           // $35
			symptomSummaryJSON,                            // $36
			diagnosisRequest.PrimaryComplaint,             // $37
			pq.Array(diagnosisRequest.SymptomCategories),  // $38
			symptomTriggersJSON,                           // $39
			symptomRelievingFactorsJSON,                   // $40
			symptomQualityDetailsJSON,                     // $41
			symptomProgressionJSON,                        // $42
			symptomRadiationPatternsJSON,                  // $43
			specializationsJSON,                           // $44 ✅ ADDED
		).Scan(&diagnosisID, &createdAt)

		if err != nil {
			h.logger.Error("failed to insert diagnosis", zap.Error(err))
			if strings.Contains(err.Error(), "duplicate key") {
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Diagnosis with this appointment already exists"})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create diagnosis"})
		}

		updatedAt = createdAt
		h.logger.Info("diagnosis created successfully",
			zap.String("diagnosis_id", diagnosisID),
			zap.String("appointment_id", diagnosisRequest.AppointmentID))
	}

	if isUpdate {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message":          "Diagnosis updated successfully",
			"diagnosis_id":     diagnosisID,
			"created_at":       createdAt,
			"updated_at":       updatedAt,
			"diagnosis_status": diagnosisRequest.Status, // Renamed to avoid confusion
			"success":          true,
		})
	} else {
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message":          "Diagnosis created successfully",
			"diagnosis_id":     diagnosisID,
			"created_at":       createdAt,
			"updated_at":       updatedAt,
			"diagnosis_status": diagnosisRequest.Status, // Renamed to avoid confusion
			"success":          true,
		})
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

// GetDiagnosis retrieves the latest diagnosis by appointment_id from URL path
func (h *DiagnosisHandler) GetDiagnosis(c *fiber.Ctx) error {
	// Get appointment_id from URL path parameters
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

	// Query to get the latest diagnosis for the appointment (more efficient than getting all and sorting)
	query := `
		SELECT
			id, appointment_id, patient_id, doctor_id, org_id, patient_name, patient_age,
			patient_gender, doctor_name, doctor_specialty, temperature, blood_pressure,
			heart_rate, weight, height, bmi, respiratory_rate, oxygen_saturation,
			chief_complaint, primary_complaint, symptoms, physical_exam,
			primary_diagnosis, secondary_diagnoses, icd_codes, medications, procedures,
			recommendations, lab_orders, test_results, specialty, specialty_data,
			follow_up_date, follow_up_notes, referrals, status, clinical_notes,
			attachments, created_at, updated_at, symptom_timeline, symptom_summary,
			symptom_categories, symptom_triggers, symptom_relieving_factors,
			symptom_quality_details, symptom_progression, symptom_radiation_patterns,
			primary_symptoms, symptom_locations, symptom_severities, symptom_durations,
			symptom_frequencies, symptom_pain_scales, symptom_onset_dates, specializations
		FROM medical_diagnoses
		WHERE appointment_id = $1
		ORDER BY created_at DESC
		LIMIT 1`

	var diagnosis DiagnosisResponse
	var symptomsJSON, medicationsJSON, testResultsJSON, attachmentsJSON []byte
	var symptomTimelineJSON, symptomSummaryJSON, symptomTriggersJSON, symptomRelievingFactorsJSON []byte
	var symptomQualityDetailsJSON, symptomProgressionJSON, symptomRadiationPatternsJSON []byte
	var primarySymptomsJSON, symptomLocationsJSON, symptomSeveritiesJSON, symptomDurationsJSON []byte
	var symptomFrequenciesJSON, symptomPainScalesJSON, symptomOnsetDatesJSON, specializationsJSON []byte

	err = h.pgPool.QueryRow(c.Context(), query, appointmentID).Scan(
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
		&diagnosis.Vitals.RespiratoryRate,
		&diagnosis.Vitals.OxygenSaturation,
		&diagnosis.ChiefComplaint,
		&diagnosis.PrimaryComplaint,
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
		&symptomTimelineJSON,
		&symptomSummaryJSON,
		&diagnosis.SymptomCategories,
		&symptomTriggersJSON,
		&symptomRelievingFactorsJSON,
		&symptomQualityDetailsJSON,
		&symptomProgressionJSON,
		&symptomRadiationPatternsJSON,
		&primarySymptomsJSON,
		&symptomLocationsJSON,
		&symptomSeveritiesJSON,
		&symptomDurationsJSON,
		&symptomFrequenciesJSON,
		&symptomPainScalesJSON,
		&symptomOnsetDatesJSON,
		&specializationsJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			h.logger.Info("no diagnosis found for appointment", zap.String("appointment_id", appointmentID))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error":   "No diagnosis found",
				"message": "No diagnosis found for the specified appointment",
			})
		}
		h.logger.Error("failed to retrieve diagnosis", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve diagnosis"})
	}

	// Parse JSON fields with error handling
	parseJSONField := func(data []byte, target interface{}, fieldName string) {
		if data != nil {
			if err := json.Unmarshal(data, target); err != nil {
				h.logger.Warn("failed to parse JSON field",
					zap.String("field", fieldName),
					zap.Error(err))
			}
		}
	}

	// Parse all JSON fields
	parseJSONField(symptomsJSON, &diagnosis.Symptoms, "symptoms")
	parseJSONField(medicationsJSON, &diagnosis.TreatmentPlan.Medications, "medications")
	parseJSONField(testResultsJSON, &diagnosis.TestResults, "test_results")
	parseJSONField(attachmentsJSON, &diagnosis.Attachments, "attachments")
	parseJSONField(symptomTimelineJSON, &diagnosis.SymptomTimeline, "symptom_timeline")
	parseJSONField(symptomSummaryJSON, &diagnosis.SymptomSummary, "symptom_summary")
	parseJSONField(symptomTriggersJSON, &diagnosis.SymptomTriggers, "symptom_triggers")
	parseJSONField(symptomRelievingFactorsJSON, &diagnosis.SymptomRelievingFactors, "symptom_relieving_factors")
	parseJSONField(symptomQualityDetailsJSON, &diagnosis.SymptomQualityDetails, "symptom_quality_details")
	parseJSONField(symptomProgressionJSON, &diagnosis.SymptomProgression, "symptom_progression")
	parseJSONField(symptomRadiationPatternsJSON, &diagnosis.SymptomRadiationPatterns, "symptom_radiation_patterns")
	parseJSONField(primarySymptomsJSON, &diagnosis.PrimarySymptoms, "primary_symptoms")
	parseJSONField(symptomLocationsJSON, &diagnosis.SymptomLocations, "symptom_locations")
	parseJSONField(symptomSeveritiesJSON, &diagnosis.SymptomSeverities, "symptom_severities")
	parseJSONField(symptomDurationsJSON, &diagnosis.SymptomDurations, "symptom_durations")
	parseJSONField(symptomFrequenciesJSON, &diagnosis.SymptomFrequencies, "symptom_frequencies")
	parseJSONField(symptomPainScalesJSON, &diagnosis.SymptomPainScales, "symptom_pain_scales")
	parseJSONField(symptomOnsetDatesJSON, &diagnosis.SymptomOnsetDates, "symptom_onset_dates")
	parseJSONField(specializationsJSON, &diagnosis.Specializations, "specializations")

	h.logger.Info("diagnosis retrieved successfully",
		zap.String("appointment_id", appointmentID),
		zap.String("diagnosis_id", diagnosis.ID))

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":   "Diagnosis retrieved successfully",
		"diagnosis": diagnosis,
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
	ID                       string         `json:"id"`
	AppointmentID            string         `json:"appointment_id"`
	PatientID                string         `json:"patient_id"`
	DoctorID                 string         `json:"doctor_id"`
	OrgID                    string         `json:"org_id"`
	PatientName              *string        `json:"patient_name"`
	PatientAge               *int           `json:"patient_age"`
	PatientGender            *string        `json:"patient_gender"`
	DoctorName               *string        `json:"doctor_name"`
	DoctorSpecialty          *string        `json:"doctor_specialty"`
	Specializations          interface{}    `json:"specializations"` // Added type for specializations
	Vitals                   VitalsResponse `json:"vitals"`
	ChiefComplaint           *string        `json:"chief_complaint"`
	PrimaryComplaint         *string        `json:"primary_complaint"`
	Symptoms                 []Symptom      `json:"symptoms"`
	SymptomTimeline          interface{}    `json:"symptom_timeline"`
	SymptomSummary           interface{}    `json:"symptom_summary"`
	SymptomCategories        []string       `json:"symptom_categories"`
	SymptomTriggers          interface{}    `json:"symptom_triggers"`
	SymptomRelievingFactors  interface{}    `json:"symptom_relieving_factors"`
	SymptomQualityDetails    interface{}    `json:"symptom_quality_details"`
	SymptomProgression       interface{}    `json:"symptom_progression"`
	SymptomRadiationPatterns interface{}    `json:"symptom_radiation_patterns"`
	PrimarySymptoms          interface{}    `json:"primary_symptoms"`
	SymptomLocations         interface{}    `json:"symptom_locations"`
	SymptomSeverities        interface{}    `json:"symptom_severities"`
	SymptomDurations         interface{}    `json:"symptom_durations"`
	SymptomFrequencies       interface{}    `json:"symptom_frequencies"`
	SymptomPainScales        interface{}    `json:"symptom_pain_scales"`
	SymptomOnsetDates        interface{}    `json:"symptom_onset_dates"`
	PhysicalExam             *string        `json:"physical_exam"`
	PrimaryDiagnosis         string         `json:"primary_diagnosis"`
	SecondaryDiagnoses       []string       `json:"secondary_diagnoses"`
	ICDCodes                 []string       `json:"icd_codes"`
	TreatmentPlan            TreatmentPlan  `json:"treatment_plan"`
	LabOrders                []string       `json:"lab_orders"`
	TestResults              []TestResult   `json:"test_results"`
	Specialty                *string        `json:"specialty"`
	SpecialtyData            interface{}    `json:"specialty_data"`
	FollowUpDate             *time.Time     `json:"follow_up_date"`
	FollowUpNotes            *string        `json:"follow_up_notes"`
	Referrals                []string       `json:"referrals"`
	Status                   string         `json:"status"`
	ClinicalNotes            *string        `json:"clinical_notes"`
	Attachments              []Attachment   `json:"attachments"`
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
}

type VitalsResponse struct {
	Temperature      *float64 `json:"temperature"`
	BloodPressure    *string  `json:"blood_pressure"`
	HeartRate        *int     `json:"heart_rate"`
	Weight           *float64 `json:"weight"`
	Height           *float64 `json:"height"`
	BMI              *float64 `json:"bmi"`
	RespiratoryRate  *int     `json:"respiratory_rate"`
	OxygenSaturation *int     `json:"oxygen_saturation"`
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
