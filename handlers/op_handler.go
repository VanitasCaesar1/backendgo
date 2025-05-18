package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

type MedicalRecord struct {
	Diagnosis    string    `json:"diagnosis" bson:"diagnosis"`
	Treatment    string    `json:"treatment" bson:"treatment"`
	Date         time.Time `json:"date" bson:"date"`
	DoctorID     string    `json:"doctor_id" bson:"doctor_id"`
	HospitalID   string    `json:"hospital_id" bson:"hospital_id"`
	Prescription string    `json:"prescription" bson:"prescription"`
}

type EmergencyContact struct {
	Name     string `json:"name" bson:"name"`
	Mobile   string `json:"mobile" bson:"mobile"`
	Address  string `json:"address" bson:"address"`
	Relation string `json:"relation" bson:"relation"`
}

type HospitalVisit struct {
	HospitalID string    `json:"hospital_id" bson:"hospital_id"`
	VisitDate  time.Time `json:"visit_date" bson:"visit_date"`
	DoctorID   string    `json:"doctor_id" bson:"doctor_id"`
	Purpose    string    `json:"purpose" bson:"purpose"`
	Diagnosis  string    `json:"diagnosis" bson:"diagnosis"`
}

// You may need to update your DoctorSearchResult struct to match the fields we're now retrieving
type DoctorSearchResult struct {
	DoctorID       uuid.UUID `json:"doctor_id"`
	Name           string    `json:"name"`
	Speciality     string    `json:"speciality"`
	Age            int       `json:"age"`
	Qualification  string    `json:"qualification"`
	IMRNumber      string    `json:"imr_number"` // Using IMRNumber instead of LicenseNumber
	HospitalName   string    `json:"hospital_name"`
	HospitalID     uuid.UUID `json:"hospital_id"`
	IsActive       bool      `json:"is_active"`
	OrganizationID string    `json:"organization_id"`
	SlotDuration   int       `json:"slot_duration"`
}

type Medical struct {
	Condition     string    `json:"condition" bson:"condition"`
	DiagnosedDate time.Time `json:"diagnosed_date" bson:"diagnosed_date"`
	Notes         string    `json:"notes,omitempty" bson:"notes,omitempty"`
}

type Contact struct {
	Name         string `json:"name" bson:"name"`
	Relationship string `json:"relationship,omitempty" bson:"relationship,omitempty"`
	Phone        string `json:"phone" bson:"phone"`
}

type Insurance struct {
	Provider        string    `json:"provider" bson:"provider"`
	PolicyNumber    string    `json:"policy_number,omitempty" bson:"policy_number,omitempty"`
	ExpiryDate      time.Time `json:"expiry_date,omitempty" bson:"expiry_date,omitempty"`
	CoverageDetails string    `json:"coverage_details,omitempty" bson:"coverage_details,omitempty"`
}

type Visit struct {
	HospitalID   string    `json:"hospital_id" bson:"hospital_id"`
	HospitalName string    `json:"hospital_name,omitempty" bson:"hospital_name,omitempty"`
	VisitDate    time.Time `json:"visit_date" bson:"visit_date"`
	Reason       string    `json:"reason,omitempty" bson:"reason,omitempty"`
}

type Patient struct {
	PatientID        string     `json:"patient_id" bson:"patient_id"`
	Name             string     `json:"name" bson:"name"`
	Email            string     `json:"email" bson:"email"`
	Mobile           string     `json:"mobile" bson:"mobile"`
	Gender           string     `json:"gender,omitempty" bson:"gender,omitempty"`
	Age              int        `json:"age,omitempty" bson:"age,omitempty"`
	BloodGroup       string     `json:"blood_group,omitempty" bson:"blood_group,omitempty"`
	Address          string     `json:"address,omitempty" bson:"address,omitempty"`
	AadhaarID        string     `json:"aadhaar_id,omitempty" bson:"aadhaar_id,omitempty"`
	MedicalHistory   []Medical  `json:"medical_history,omitempty" bson:"medical_history,omitempty"`
	Allergies        []string   `json:"allergies,omitempty" bson:"allergies,omitempty"`
	EmergencyContact *Contact   `json:"emergency_contact,omitempty" bson:"emergency_contact,omitempty"`
	Insurance        *Insurance `json:"insurance,omitempty" bson:"insurance,omitempty"`
	HospitalVisits   []Visit    `json:"hospital_visits,omitempty" bson:"hospital_visits,omitempty"`
	AuthID           string     `json:"auth_id" bson:"auth_id"`
	CreatedAt        time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at" bson:"updated_at"`
}

// PatientSearchResult represents a limited view of patient data for search results
type PatientSearchResult struct {
	PatientID  string `json:"patient_id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Mobile     string `json:"mobile"`
	Age        int    `json:"age,omitempty"`
	BloodGroup string `json:"blood_group,omitempty"`
	Address    string `json:"address,omitempty"`
}

// AppointmentRequest represents the appointment creation request
type AppointmentRequest struct {
	PatientID       string    `json:"patient_id"`
	DoctorID        string    `json:"doctor_id"`
	HospitalID      string    `json:"hospital_id"`
	AppointmentDate time.Time `json:"appointment_date"`
	PaymentMethod   string    `json:"payment_method"`
	FeeType         string    `json:"fee_type"`
	AppointmentFee  int       `json:"appointment_fee"`
}

// Appointment represents the structure of an appointment in the database
type Appointment struct {
	AppointmentID     string    `bson:"appointment_id" json:"appointment_id"`
	PatientID         string    `bson:"patient_id" json:"patient_id"`
	DoctorID          string    `bson:"doctor_id" json:"doctor_id"`
	OrgID             string    `bson:"org_id" json:"org_id"`
	PatientName       string    `bson:"patient_name" json:"patient_name"`
	DoctorName        string    `bson:"doctor_name" json:"doctor_name"`
	AppointmentStatus string    `bson:"appointment_status" json:"appointment_status"`
	PaymentMethod     string    `bson:"payment_method" json:"payment_method"`
	FeeType           string    `bson:"fee_type" json:"fee_type"`
	AppointmentFee    int       `bson:"appointment_fee" json:"appointment_fee"`
	AppointmentDate   time.Time `bson:"appointment_date,omitempty" json:"appointment_date,omitempty"`
	CreatedAt         time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time `bson:"updated_at,omitempty" json:"updated_at,omitempty"`
	IsValid           bool      `bson:"is_valid" json:"is_valid"`
	NextVisitDate     time.Time `bson:"next_visit_date" json:"next_visit_date"`
	SlotStartTime     string    `bson:"slot_start_time" json:"slot_start_time"`
	SlotEndTime       string    `bson:"slot_end_time" json:"slot_end_time"`
}

// Define response type for clarity
type AppointmentResponse struct {
	ID                string `json:"id"`
	AppointmentID     string `json:"appointment_id"`
	PatientID         string `json:"patient_id"`
	DoctorID          string `json:"doctor_id"`
	OrgID             string `json:"org_id"`
	PatientName       string `json:"patient_name"`
	DoctorName        string `json:"doctor_name"`
	AppointmentStatus string `json:"appointment_status"`
	PaymentMethod     string `json:"payment_method"`
	FeeType           string `json:"fee_type"`
	AppointmentFee    int    `json:"appointment_fee"`
	AppointmentDate   string `json:"appointment_date"`
	NextVisitDate     string `json:"next_visit_date"`
	IsValid           bool   `json:"is_valid"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
	SlotStartTime     string `json:"slot_start_time"`
	SlotEndTime       string `json:"slot_end_time"`
}

type AppointmentFilters struct {
	DoctorID          string `query:"doctor_id"`
	PatientID         string `query:"patient_id"`
	AppointmentStatus string `query:"appointment_status"`
	FeeType           string `query:"fee_type"`
	StartDate         string `query:"start_date"`
	EndDate           string `query:"end_date"`
	Limit             int64  `query:"limit"`
	Offset            int64  `query:"offset"`
	SortBy            string `query:"sort_by"`
	SortOrder         string `query:"sort_order"`
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

// buildAppointmentQuery constructs a MongoDB query based on filters
func buildAppointmentQuery(orgID string, filters AppointmentFilters) bson.M {
	// Start with the base query that always includes org_id and is_valid=true
	query := bson.M{
		"org_id":   orgID,
		"is_valid": true,
	}

	// Add doctor_id filter if specified and not "all"
	if filters.DoctorID != "" && filters.DoctorID != "all" {
		query["doctor_id"] = filters.DoctorID
	}

	// Add patient_id filter if specified and not "all"
	if filters.PatientID != "" && filters.PatientID != "all" {
		query["patient_id"] = filters.PatientID
	}

	// Add appointment_status filter if specified and not "all"
	if filters.AppointmentStatus != "" && filters.AppointmentStatus != "all" {
		query["appointment_status"] = filters.AppointmentStatus
	}

	// Add fee_type filter if specified and not "all"
	if filters.FeeType != "" && filters.FeeType != "all" {
		query["fee_type"] = filters.FeeType
	}

	// Add date range filters if specified
	dateQuery := bson.M{}
	if filters.StartDate != "" {
		// Parse start date and set to beginning of day
		startDate, err := time.Parse("2006-01-02", filters.StartDate)
		if err != nil {
			// Handle error gracefully, log it but continue
			log.Printf("Error parsing start date: %v", err)
		} else {
			dateQuery["$gte"] = startDate
		}
	}

	if filters.EndDate != "" {
		// Parse end date and set to end of day
		endDate, err := time.Parse("2006-01-02", filters.EndDate)
		if err != nil {
			// Handle error gracefully, log it but continue
			log.Printf("Error parsing end date: %v", err)
		} else {
			// Add 24 hours to include the entire end date
			endDate = endDate.Add(24 * time.Hour)
			dateQuery["$lt"] = endDate
		}
	}

	// Add date range to query if any date filters were applied
	if len(dateQuery) > 0 {
		query["appointment_date"] = dateQuery
	}

	return query
}

// processAppointments converts the MongoDB cursor to a slice of appointments
func processAppointments(cursor *mongo.Cursor, ctx context.Context) ([]Appointment, error) {
	var appointments []Appointment

	for cursor.Next(ctx) {
		var appointment Appointment
		err := cursor.Decode(&appointment)
		if err != nil {
			return nil, err
		}
		appointments = append(appointments, appointment)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return appointments, nil
}

// GetAppointmentsByOrgID retrieves appointments based on org_id from X-Organization-ID header
func (h *AppointmentHandler) GetAppointmentsByOrgID(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get organization ID from request headers
	orgID := c.Get("X-Organization-ID")
	if orgID == "" {
		h.logger.Error("organization ID not found in headers")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required in X-Organization-ID header"})
	}

	// Log all headers for debugging
	headers := c.GetReqHeaders()
	h.logger.Debug("All request headers", zap.Any("headers", headers))

	// Validate org ID format
	if !validateOrgID(orgID) {
		h.logger.Error("invalid organization ID format", zap.String("orgID", orgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Invalid organization ID format",
			"details": "Organization ID must be in ULID format with org_ prefix",
		})
	}

	h.logger.Info("Processing request",
		zap.String("Auth ID", authID),
		zap.String("Org ID", orgID))

	// Extract all query parameters
	var filters AppointmentFilters

	// Log all query parameters for debugging
	h.logger.Debug("Request query parameters", zap.Any("params", c.Queries()))

	// Parse query parameters individually to handle name differences
	filters.DoctorID = c.Query("doctor_id")
	filters.PatientID = c.Query("patient_id")
	filters.AppointmentStatus = c.Query("appointment_status")
	filters.FeeType = c.Query("fee_type")
	filters.StartDate = c.Query("start_date")
	filters.EndDate = c.Query("end_date")

	// Parse numeric parameters with defaults
	limitStr := c.Query("limit", "10")
	offsetStr := c.Query("offset", "0")

	limit, err := strconv.ParseInt(limitStr, 10, 64)
	if err != nil || limit < 1 {
		limit = 10
	}
	filters.Limit = limit

	offset, err := strconv.ParseInt(offsetStr, 10, 64)
	if err != nil || offset < 0 {
		offset = 0
	}
	filters.Offset = offset

	// Parse sorting parameters
	filters.SortBy = c.Query("sort_by", "created_at")
	filters.SortOrder = c.Query("sort_order", "desc")

	// Apply validation and defaults to filters
	if err := validateAndSetFilterDefaults(&filters); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Build MongoDB query
	query := buildAppointmentQuery(orgID, filters)

	// Print debug info for troubleshooting
	h.logger.Debug("MongoDB query", zap.Any("query", query))

	// Configure find options and determine sort direction
	findOptions := options.Find()
	findOptions.SetLimit(filters.Limit)
	findOptions.SetSkip(filters.Offset)

	// Set sort order
	sortDirection := -1 // Default to descending
	if filters.SortOrder == "asc" {
		sortDirection = 1
	}
	findOptions.SetSort(bson.D{{Key: filters.SortBy, Value: sortDirection}})

	// Query MongoDB
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")

	// Add debug logging to verify collection exists
	collections, err := h.mongoClient.Database(h.config.MongoDBName).ListCollectionNames(c.Context(), bson.M{})
	if err != nil {
		h.logger.Error("failed to list collections", zap.Error(err))
	} else {
		h.logger.Debug("Available collections", zap.Strings("collections", collections))
	}

	// Execute query with timeout context
	ctx, cancel := context.WithTimeout(c.Context(), 15*time.Second)
	defer cancel()

	cursor, err := appointmentsCollection.Find(ctx, query, findOptions)
	if err != nil {
		h.logger.Error("failed to query appointments",
			zap.Error(err),
			zap.String("orgID", orgID),
			zap.Any("query", query))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch appointments"})
	}
	defer cursor.Close(ctx)

	// Process appointments
	appointments, err := processAppointments(cursor, ctx)
	if err != nil {
		h.logger.Error("error processing appointments", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error processing appointments"})
	}

	// Get total count for pagination
	total, err := appointmentsCollection.CountDocuments(ctx, query)
	if err != nil {
		h.logger.Error("failed to count appointments", zap.Error(err))
		total = 0 // Continue with the results but without total count
	}

	// Log result count
	h.logger.Info("Retrieved appointments",
		zap.Int("count", len(appointments)),
		zap.Int64("total", total))

	return c.JSON(fiber.Map{
		"appointments": appointments,
		"pagination": fiber.Map{
			"total":  total,
			"limit":  filters.Limit,
			"offset": filters.Offset,
		},
	})
}

// validateAndSetFilterDefaults validates filter parameters and applies default values
func validateAndSetFilterDefaults(filters *AppointmentFilters) error {
	// Validate doctor_id if provided
	if filters.DoctorID != "" && filters.DoctorID != "all" {
		if !validateUUID(filters.DoctorID) {
			return fmt.Errorf("invalid doctor ID format: must be in UUID format")
		}
	}

	// Validate patient_id if provided
	if filters.PatientID != "" && filters.PatientID != "all" {
		if !validatePatientID(filters.PatientID) {
			return fmt.Errorf("invalid patient ID format: must be an 8-digit alphanumeric code")
		}
	}

	// Validate appointment status
	if filters.AppointmentStatus != "" && filters.AppointmentStatus != "all" {
		if filters.AppointmentStatus != "completed" && filters.AppointmentStatus != "not_completed" {
			return fmt.Errorf("invalid appointment status: must be 'completed', 'not_completed', or 'all'")
		}
	}

	// Validate fee type
	if filters.FeeType != "" && filters.FeeType != "all" {
		if filters.FeeType != "emergency" && filters.FeeType != "default" && filters.FeeType != "recurring" {
			return fmt.Errorf("invalid fee type: must be 'emergency', 'default', 'recurring', or 'all'")
		}
	}

	// Validate date formats
	if filters.StartDate != "" {
		if !validateDateFormat(filters.StartDate) {
			return fmt.Errorf("invalid start date format: must be in YYYY-MM-DD format")
		}
	}

	if filters.EndDate != "" {
		if !validateDateFormat(filters.EndDate) {
			return fmt.Errorf("invalid end date format: must be in YYYY-MM-DD format")
		}
	}

	// Apply default limit if not valid
	if filters.Limit <= 0 || filters.Limit > 100 {
		filters.Limit = 10 // Default to 10
	}

	// Apply default offset if not valid
	if filters.Offset < 0 {
		filters.Offset = 0 // Default to 0
	}

	// Validate and apply default sort field
	validSortFields := []string{
		"created_at",
		"appointment_date",
		"appointment_fee",
		"appointment_status",
		"next_visit_date",
	}

	if !contains(validSortFields, filters.SortBy) {
		filters.SortBy = "created_at" // Default sort field
	}

	// Validate and apply default sort order
	if filters.SortOrder != "asc" && filters.SortOrder != "desc" {
		filters.SortOrder = "desc" // Default to descending
	}

	return nil
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

// Helper function to validate Patient ID format (8-digit alphanumeric ID)
func validatePatientID(id string) bool {
	patientIDRegex := regexp.MustCompile(`^[A-Z0-9]{8}$`)
	return patientIDRegex.MatchString(id)
}

// validateUUID checks if a string is a valid UUID
func validateUUID(id string) bool {
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return uuidRegex.MatchString(id)
}

// validateOrgID checks if a string is a valid organization ID
func validateOrgID(id string) bool {
	orgIDRegex := regexp.MustCompile(`^org_[A-Z0-9]{26}$`)
	return orgIDRegex.MatchString(id)
}

// validateDateFormat checks if a string is in YYYY-MM-DD format
func validateDateFormat(date string) bool {
	dateRegex := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	return dateRegex.MatchString(date)
}

// Helper function to validate doctor ID format (UUID)
func validateDoctorID(doctorID string) bool {
	return regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`).MatchString(doctorID)
}

// Helper function to parse time with multiple possible formats
func parseTimeWithFallbacks(timeStr string) (time.Time, error) {
	formats := []string{
		"15:04:05",
		"15:04",
		"3:04 PM",
		"3:04:05 PM",
	}

	for _, format := range formats {
		t, err := time.Parse(format, timeStr)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("could not parse time from %s", timeStr)
}

// Set default isValid if not provided// Helper functions to improve readability and maintainability
func (h *AppointmentHandler) CreateAppointment(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	fmt.Println("Auth ID:", authID)
	// Log raw request body for debugging
	var rawBody map[string]interface{}
	if err := c.BodyParser(&rawBody); err != nil {
		h.logger.Error("failed to parse raw request body", zap.Error(err))
	} else {
		h.logger.Debug("raw request body", zap.Any("body", rawBody))
	}

	// Reset request body for the actual parsing
	c.Request().SetBody(c.Request().Body())

	// Parse appointment data from request body
	var appointmentRequest struct {
		PatientID         string    `json:"patient_id"`
		DoctorID          string    `json:"doctor_id"`
		OrgID             string    `json:"org_id"`
		PatientName       string    `json:"patient_name"`
		DoctorName        string    `json:"doctor_name"`
		AppointmentDate   time.Time `json:"appointment_date"`
		SlotStartTime     string    `json:"slot_start_time"` // New field for slot start time
		SlotEndTime       string    `json:"slot_end_time"`   // New field for slot end time
		FeeType           string    `json:"fee_type"`
		PaymentMethod     string    `json:"payment_method"`
		Reason            string    `json:"reason,omitempty"` // Optional field
		AppointmentStatus string    `json:"appointment_status,omitempty"`
		AppointmentFee    int       `json:"appointment_fee,omitempty"`
		IsValid           *bool     `json:"is_valid,omitempty"`
	}

	if err := c.BodyParser(&appointmentRequest); err != nil {
		h.logger.Error("failed to parse appointment data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment data: " + err.Error()})
	}

	// Log the parsed request for debugging
	h.logger.Debug("parsed appointment request",
		zap.String("patient_id", appointmentRequest.PatientID),
		zap.String("doctor_id", appointmentRequest.DoctorID),
		zap.String("org_id", appointmentRequest.OrgID),
		zap.String("patient_name", appointmentRequest.PatientName),
		zap.String("doctor_name", appointmentRequest.DoctorName),
		zap.Any("appointment_date", appointmentRequest.AppointmentDate),
		zap.String("slot_start_time", appointmentRequest.SlotStartTime),
		zap.String("slot_end_time", appointmentRequest.SlotEndTime),
		zap.String("fee_type", appointmentRequest.FeeType),
		zap.String("payment_method", appointmentRequest.PaymentMethod))

	// Check required fields individually and log which ones are missing
	var missingFields []string
	if appointmentRequest.PatientID == "" {
		missingFields = append(missingFields, "patient_id")
	}
	if appointmentRequest.DoctorID == "" {
		missingFields = append(missingFields, "doctor_id")
	}
	if appointmentRequest.OrgID == "" {
		missingFields = append(missingFields, "org_id")
	}
	if appointmentRequest.PatientName == "" {
		missingFields = append(missingFields, "patient_name")
	}
	if appointmentRequest.DoctorName == "" {
		missingFields = append(missingFields, "doctor_name")
	}
	if appointmentRequest.AppointmentDate.IsZero() {
		missingFields = append(missingFields, "appointment_date")
	}
	if appointmentRequest.SlotStartTime == "" {
		missingFields = append(missingFields, "slot_start_time")
	}
	if appointmentRequest.SlotEndTime == "" {
		missingFields = append(missingFields, "slot_end_time")
	}
	if appointmentRequest.FeeType == "" {
		missingFields = append(missingFields, "fee_type")
	}
	if appointmentRequest.PaymentMethod == "" {
		missingFields = append(missingFields, "payment_method")
	}

	if len(missingFields) > 0 {
		h.logger.Error("missing specific required fields in appointment request",
			zap.Strings("missing_fields", missingFields))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Missing required fields: %s", strings.Join(missingFields, ", ")),
		})
	}

	// Validate ID formats based on schema requirements
	if !validatePatientID(appointmentRequest.PatientID) {
		h.logger.Warn("invalid patient ID format", zap.String("patient_id", appointmentRequest.PatientID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Patient ID must be 8-digit alphanumeric format"})
	}

	if !validateDoctorID(appointmentRequest.DoctorID) {
		h.logger.Warn("invalid doctor ID format", zap.String("doctor_id", appointmentRequest.DoctorID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor ID must be in UUID format"})
	}

	if !validateOrgID(appointmentRequest.OrgID) {
		h.logger.Warn("invalid organization ID format", zap.String("org_id", appointmentRequest.OrgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID must be in ULID format (org_[A-Z0-9]{26})"})
	}

	// Validate time slot format (expected format: "HH:MM")
	if !validateTimeFormat(appointmentRequest.SlotStartTime) {
		h.logger.Warn("invalid slot start time format", zap.String("slot_start_time", appointmentRequest.SlotStartTime))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Slot start time must be in HH:MM format (24-hour)"})
	}

	if !validateTimeFormat(appointmentRequest.SlotEndTime) {
		h.logger.Warn("invalid slot end time format", zap.String("slot_end_time", appointmentRequest.SlotEndTime))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Slot end time must be in HH:MM format (24-hour)"})
	}

	// Validate that start time is before end time
	if !validateTimeRange(appointmentRequest.SlotStartTime, appointmentRequest.SlotEndTime) {
		h.logger.Warn("invalid time slot range",
			zap.String("slot_start_time", appointmentRequest.SlotStartTime),
			zap.String("slot_end_time", appointmentRequest.SlotEndTime))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Slot start time must be before slot end time"})
	}

	// Validate fee type
	if appointmentRequest.FeeType != "emergency" && appointmentRequest.FeeType != "default" && appointmentRequest.FeeType != "recurring" {
		h.logger.Warn("invalid fee type", zap.String("fee_type", appointmentRequest.FeeType))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Fee type must be emergency, default, or recurring"})
	}

	// Verify doctor availability for the selected time slot
	h.logger.Debug("checking doctor availability",
		zap.String("doctor_id", appointmentRequest.DoctorID),
		zap.Time("appointment_date", appointmentRequest.AppointmentDate),
		zap.String("slot_start_time", appointmentRequest.SlotStartTime),
		zap.String("slot_end_time", appointmentRequest.SlotEndTime))

	available, err := h.checkDoctorAvailabilityForSlot(c.Context(),
		appointmentRequest.DoctorID,
		appointmentRequest.OrgID,
		appointmentRequest.AppointmentDate,
		appointmentRequest.SlotStartTime,
		appointmentRequest.SlotEndTime)
	if err != nil {
		h.logger.Error("failed to check doctor availability", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to check doctor availability"})
	}

	if !available {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor is not available during the selected time slot"})
	}

	// Get doctor's fees based on fee type
	h.logger.Debug("getting doctor fees",
		zap.String("doctor_id", appointmentRequest.DoctorID),
		zap.String("org_id", appointmentRequest.OrgID),
		zap.String("fee_type", appointmentRequest.FeeType))

	appointmentFee, err := h.getDoctorFee(c.Context(), appointmentRequest.DoctorID, appointmentRequest.OrgID, appointmentRequest.FeeType)
	if err != nil {
		h.logger.Warn("failed to get doctor fees, using default", zap.Error(err))
		appointmentFee = h.getDefaultFee(appointmentRequest.FeeType)
	}

	h.logger.Debug("determined appointment fee", zap.Int("fee", appointmentFee))

	// If client provided a fee, log it but still use our calculated value
	if appointmentRequest.AppointmentFee > 0 {
		h.logger.Debug("client provided fee ignored",
			zap.Int("client_fee", appointmentRequest.AppointmentFee),
			zap.Int("calculated_fee", appointmentFee))
	}

	// Calculate next visit date (required by schema)
	// Default to 30 days after the appointment date for recurring, 90 days for others
	nextVisitDate := appointmentRequest.AppointmentDate
	if appointmentRequest.FeeType == "recurring" {
		nextVisitDate = nextVisitDate.AddDate(0, 0, 30) // 30 days later
	} else {
		nextVisitDate = nextVisitDate.AddDate(0, 0, 90) // 90 days later
	}

	// Set default appointment status if not provided
	appointmentStatus := "not_completed"
	if appointmentRequest.AppointmentStatus == "completed" {
		appointmentStatus = "completed"
	}

	// Set default isValid if not provided
	isValid := true
	if appointmentRequest.IsValid != nil {
		isValid = *appointmentRequest.IsValid
	}

	// Generate a new UUID for appointment_id
	appointmentID := uuid.New().String()
	h.logger.Debug("generated appointment_id", zap.String("appointment_id", appointmentID))

	// Create appointment document (using field names that match the schema)
	now := time.Now()
	appointment := bson.M{
		"appointment_id":     appointmentID, // Added required appointment_id field
		"patient_id":         appointmentRequest.PatientID,
		"doctor_id":          appointmentRequest.DoctorID,
		"org_id":             appointmentRequest.OrgID,
		"patient_name":       appointmentRequest.PatientName,
		"doctor_name":        appointmentRequest.DoctorName,
		"appointment_status": appointmentStatus,
		"payment_method":     appointmentRequest.PaymentMethod,
		"fee_type":           appointmentRequest.FeeType,
		"appointment_fee":    appointmentFee,
		"appointment_date":   appointmentRequest.AppointmentDate,
		"slot_start_time":    appointmentRequest.SlotStartTime,
		"slot_end_time":      appointmentRequest.SlotEndTime,
		"created_at":         now,
		"updated_at":         now,
		"is_valid":           isValid,
		"next_visit_date":    nextVisitDate,
	}

	// Add optional reason field if provided
	if appointmentRequest.Reason != "" {
		appointment["reason"] = appointmentRequest.Reason
	}

	// Log the final document we're about to insert
	h.logger.Debug("final appointment document for insertion", zap.Any("appointment", appointment))

	// Insert appointment into MongoDB
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	result, err := appointmentsCollection.InsertOne(c.Context(), appointment)
	if err != nil {
		h.logger.Error("failed to insert appointment", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create appointment: " + err.Error()})
	}

	h.logger.Info("appointment created successfully",
		zap.Any("insertedID", result.InsertedID),
		zap.String("appointment_id", appointmentID))

	// Add ID to appointment response
	appointment["_id"] = result.InsertedID

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":     "Appointment created successfully",
		"appointment": appointment,
	})
}

// Helper function to validate time format (HH:MM in 24-hour format)
func validateTimeFormat(timeStr string) bool {
	_, err := time.Parse("15:04", timeStr)
	return err == nil
}

// Helper function to validate that start time is before end time
func validateTimeRange(startTime, endTime string) bool {
	start, err1 := time.Parse("15:04", startTime)
	end, err2 := time.Parse("15:04", endTime)

	if err1 != nil || err2 != nil {
		return false
	}

	return start.Before(end)
}

// Fix for the checkDoctorAvailabilityForSlot function
func (h *AppointmentHandler) checkDoctorAvailabilityForSlot(
	ctx context.Context,
	doctorID string,
	orgID string,
	appointmentDate time.Time,
	slotStartTime string,
	slotEndTime string,
) (bool, error) {
	// Get the weekday for the appointment date
	weekday := appointmentDate.Weekday().String()

	h.logger.Info("Checking doctor availability",
		zap.String("doctor_id", doctorID),
		zap.String("org_id", orgID),
		zap.Time("appointment_date", appointmentDate),
		zap.String("weekday", weekday),
		zap.String("slot_start_time", slotStartTime),
		zap.String("slot_end_time", slotEndTime))

	// Step 1: Check if the doctor has a shift defined for this weekday in PostgreSQL
	var startTimeStr, endTimeStr string
	var isActive bool
	var slotDuration int

	query := `
		SELECT ds.starttime::text, ds.endtime::text, ds.isactive, d.slot_duration 
		FROM doctorshifts ds
		JOIN doctors d ON ds.doctor_id = d.doctor_id
		WHERE ds.doctor_id = $1 
		AND ds.weekday = $2 
		AND ds.organization_id = $3
	`

	err := h.pgPool.QueryRow(ctx, query, doctorID, weekday, orgID).Scan(
		&startTimeStr,
		&endTimeStr,
		&isActive,
		&slotDuration,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			h.logger.Info("No shift found for doctor on this day",
				zap.String("doctor_id", doctorID),
				zap.String("weekday", weekday))
			return false, nil
		}
		h.logger.Error("Error fetching doctor shift", zap.Error(err))
		return false, err
	}

	// If shift is not active or no times set
	if !isActive || startTimeStr == "" || endTimeStr == "" {
		h.logger.Info("Shift is not active for this day",
			zap.String("doctor_id", doctorID),
			zap.Bool("is_active", isActive))
		return false, nil
	}

	// Parse shift start and end times
	shiftStart, err := parseTimeWithFallbacks(startTimeStr)
	if err != nil {
		h.logger.Error("Error parsing shift start time", zap.Error(err))
		return false, fmt.Errorf("invalid shift start time: %w", err)
	}

	shiftEnd, err := parseTimeWithFallbacks(endTimeStr)
	if err != nil {
		h.logger.Error("Error parsing shift end time", zap.Error(err))
		return false, fmt.Errorf("invalid shift end time: %w", err)
	}

	// Parse requested slot times
	requestedStart, err := time.Parse("15:04", slotStartTime)
	if err != nil {
		h.logger.Error("Error parsing requested start time", zap.Error(err))
		return false, fmt.Errorf("invalid slot start time: %w", err)
	}

	requestedEnd, err := time.Parse("15:04", slotEndTime)
	if err != nil {
		h.logger.Error("Error parsing requested end time", zap.Error(err))
		return false, fmt.Errorf("invalid slot end time: %w", err)
	}

	// Step 2: Check if the requested time slot is within the doctor's working hours
	// Normalize times for comparison (strip date part)
	normalizedRequestedStart := time.Date(0, 1, 1, requestedStart.Hour(), requestedStart.Minute(), 0, 0, time.UTC)
	normalizedRequestedEnd := time.Date(0, 1, 1, requestedEnd.Hour(), requestedEnd.Minute(), 0, 0, time.UTC)
	normalizedShiftStart := time.Date(0, 1, 1, shiftStart.Hour(), shiftStart.Minute(), 0, 0, time.UTC)
	normalizedShiftEnd := time.Date(0, 1, 1, shiftEnd.Hour(), shiftEnd.Minute(), 0, 0, time.UTC)

	// Check if requested slot is within doctor's shift hours
	if normalizedRequestedStart.Before(normalizedShiftStart) || normalizedRequestedEnd.After(normalizedShiftEnd) {
		h.logger.Info("Requested time slot is outside doctor's working hours",
			zap.String("shift_start", startTimeStr),
			zap.String("shift_end", endTimeStr),
			zap.String("requested_start", slotStartTime),
			zap.String("requested_end", slotEndTime))
		return false, nil
	}

	// Step 3: Check for existing appointments during this time slot
	// Create start and end of day for date filtering
	startOfDay := time.Date(appointmentDate.Year(), appointmentDate.Month(), appointmentDate.Day(), 0, 0, 0, 0, appointmentDate.Location())
	endOfDay := startOfDay.AddDate(0, 0, 1)

	// FIX: Improved MongoDB query for overlapping time slots
	// This query properly combines date/doctor filtering with time overlap check
	filter := bson.M{
		"doctor_id": doctorID,
		"org_id":    orgID,
		"appointment_date": bson.M{
			"$gte": primitive.NewDateTimeFromTime(startOfDay),
			"$lt":  primitive.NewDateTimeFromTime(endOfDay),
		},
		"is_valid": true,
		"appointment_status": bson.M{
			"$nin": []string{"cancelled", "declined"},
		},
		// Use the proper time overlap check conditions within the main filter
		"$and": []bson.M{
			{
				"slot_start_time": bson.M{"$lt": slotEndTime}, // Existing appointment starts before requested slot ends
			},
			{
				"slot_end_time": bson.M{"$gt": slotStartTime}, // Existing appointment ends after requested slot starts
			},
		},
	}

	// Execute MongoDB query
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	count, err := appointmentsCollection.CountDocuments(ctx, filter)
	if err != nil {
		h.logger.Error("Error checking for conflicting appointments", zap.Error(err))
		return false, err
	}

	// If count > 0, there are conflicting appointments
	if count > 0 {
		h.logger.Info("Found conflicting appointments for requested time slot",
			zap.Int64("conflict_count", count),
			zap.String("slot_start", slotStartTime),
			zap.String("slot_end", slotEndTime))
		return false, nil
	}

	h.logger.Info("Time slot is available",
		zap.String("doctor_id", doctorID),
		zap.String("slot_start", slotStartTime),
		zap.String("slot_end", slotEndTime))

	return true, nil
}

// Helper function to get default fee based on type
func (h *AppointmentHandler) getDefaultFee(feeType string) int {
	switch feeType {
	case "emergency":
		return 200
	case "recurring":
		return 100
	default:
		return 150
	}
}

// Helper function to get doctor fee
func (h *AppointmentHandler) getDoctorFee(ctx context.Context, doctorID, orgID, feeType string) (int, error) {
	// SQL query to get fees from doctor_fees table
	query := `
		SELECT 
			CASE 
				WHEN $3 = 'emergency' THEN emergency_fees
				WHEN $3 = 'recurring' THEN recurring_fees
				ELSE default_fees
			END as fee
		FROM public.doctor_fees
		WHERE doctor_id = $1 AND organization_id = $2
	`

	// Execute query
	var fee int
	err := h.pgPool.QueryRow(ctx, query, doctorID, orgID, feeType).Scan(&fee)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, fmt.Errorf("no fee found for doctor %s in organization %s", doctorID, orgID)
		}
		return 0, fmt.Errorf("database error: %w", err)
	}

	// Ensure fee is valid
	if fee <= 0 {
		return 0, fmt.Errorf("invalid fee value: %d", fee)
	}

	return fee, nil
}

func (h *AppointmentHandler) GetSlotAvailability(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	h.logger.Info("Auth ID:", zap.String("auth_id", authID))

	// Get doctor ID from params
	doctorID := c.Params("id")
	if doctorID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor ID is required"})
	}

	// Get org ID from query params with better error message
	orgID := c.Query("org_id")
	if orgID == "" {
		h.logger.Error("Missing organization ID in request", zap.String("doctor_id", doctorID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID is required in the query parameters"})
	}

	// Get date from query params
	dateStr := c.Query("date")
	if dateStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Date is required"})
	}

	// Parse date with error logging
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.logger.Error("Invalid date format", zap.String("date", dateStr), zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid date format. Use YYYY-MM-DD",
		})
	}

	// Get weekday
	weekday := date.Weekday().String()
	h.logger.Info("Fetching availability",
		zap.String("doctor_id", doctorID),
		zap.String("org_id", orgID),
		zap.String("date", dateStr),
		zap.String("weekday", weekday))

	// Get doctor shift for the weekday
	var startTimeStr, endTimeStr string
	var isActive bool
	var slotDuration int

	// Join with doctors table to get slot_duration
	query := `
        SELECT ds.starttime::text, ds.endtime::text, ds.isactive, d.slot_duration 
        FROM doctorshifts ds
        JOIN doctors d ON ds.doctor_id = d.doctor_id
        WHERE ds.doctor_id = $1 
        AND ds.weekday = $2 
        AND ds.organization_id = $3
    `

	// Log the query being executed
	h.logger.Info("Executing query",
		zap.String("query", query),
		zap.String("doctor_id", doctorID),
		zap.String("weekday", weekday),
		zap.String("org_id", orgID))

	err = h.pgPool.QueryRow(c.Context(), query, doctorID, weekday, orgID).Scan(
		&startTimeStr,
		&endTimeStr,
		&isActive,
		&slotDuration,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			h.logger.Info("No shift found for doctor",
				zap.String("doctor_id", doctorID),
				zap.String("weekday", weekday))

			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"available_slots": []string{},
				"message":         "No shift scheduled for this day",
			})
		}

		h.logger.Error("Error fetching doctor shift",
			zap.String("doctor_id", doctorID),
			zap.String("weekday", weekday),
			zap.Error(err))

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch doctor shift: " + err.Error(),
		})
	}

	// Log the shift details that were found
	h.logger.Info("Shift found",
		zap.String("doctor_id", doctorID),
		zap.String("start_time", startTimeStr),
		zap.String("end_time", endTimeStr),
		zap.Bool("is_active", isActive),
		zap.Int("slot_duration", slotDuration))

	// If shift is not active or no times set
	if !isActive || startTimeStr == "" || endTimeStr == "" {
		h.logger.Info("Shift is not active",
			zap.String("doctor_id", doctorID),
			zap.Bool("is_active", isActive))

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"available_slots": []string{},
			"message":         "No active shift for this day",
		})
	}

	// Parse start and end times, handling potential format issues
	startTime, err := parseTimeWithFallbacks(startTimeStr)
	if err != nil {
		h.logger.Error("Error parsing start time",
			zap.String("time", startTimeStr),
			zap.Error(err))

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid shift start time format: " + startTimeStr,
		})
	}

	endTime, err := parseTimeWithFallbacks(endTimeStr)
	if err != nil {
		h.logger.Error("Error parsing end time",
			zap.String("time", endTimeStr),
			zap.Error(err))

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid shift end time format: " + endTimeStr,
		})
	}

	// Use default slot duration if not set
	if slotDuration <= 0 {
		h.logger.Info("Using default slot duration of 30 minutes",
			zap.String("doctor_id", doctorID))
		slotDuration = 30 // Default 30 minutes
	}

	// Calculate all possible time slots
	var allSlots []string
	currentTime := startTime
	for currentTime.Before(endTime) {
		timeStr := currentTime.Format("15:04")
		allSlots = append(allSlots, timeStr)
		currentTime = currentTime.Add(time.Duration(slotDuration) * time.Minute)
	}

	h.logger.Info("Generated potential time slots",
		zap.Int("slot_count", len(allSlots)),
		zap.Strings("slots", allSlots))

	// Get unavailable slots (existing appointments) from MongoDB
	var bookedSlots []string

	// Create start and end of day for date filtering
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	endOfDay := startOfDay.AddDate(0, 0, 1)

	// Create MongoDB query filter for appointments on the specified date
	filter := bson.M{
		"doctor_id": doctorID,
		"org_id":    orgID,
		// Filter by appointments on this date
		"appointment_date": bson.M{
			"$gte": primitive.NewDateTimeFromTime(startOfDay),
			"$lt":  primitive.NewDateTimeFromTime(endOfDay),
		},
		// Exclude cancelled or declined appointments
		"appointment_status": bson.M{
			"$nin": []string{"cancelled", "declined"},
		},
	}

	h.logger.Info("Checking for booked slots",
		zap.Any("filter", filter))

	// Execute MongoDB query
	ctx := c.Context()
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	cursor, err := appointmentsCollection.Find(ctx, filter)

	if err != nil {
		h.logger.Error("Error querying MongoDB for appointments", zap.Error(err))
		// Continue with empty booked slots instead of returning error
		bookedSlots = []string{}
	} else {
		defer cursor.Close(ctx)

		// Define a struct to hold the appointment data we need
		type AppointmentTime struct {
			SlotStartTime string `bson:"slot_start_time"`
			SlotEndTime   string `bson:"slot_end_time"`
		}

		// Iterate through the results and extract the time slots
		for cursor.Next(ctx) {
			var appointment AppointmentTime
			if err := cursor.Decode(&appointment); err != nil {
				h.logger.Error("Error decoding appointment", zap.Error(err))
				continue
			}

			// Add both the start and end times to booked slots
			bookedSlots = append(bookedSlots, appointment.SlotStartTime)

			// Calculate intermediate slots that should also be marked as unavailable
			startSlot, err := time.Parse("15:04", appointment.SlotStartTime)
			if err == nil {
				endSlot, err := time.Parse("15:04", appointment.SlotEndTime)
				if err == nil {
					// Mark intermediate slots as booked
					intermediateTime := startSlot.Add(time.Duration(slotDuration) * time.Minute)
					for intermediateTime.Before(endSlot) {
						intermediateSlot := intermediateTime.Format("15:04")
						bookedSlots = append(bookedSlots, intermediateSlot)
						intermediateTime = intermediateTime.Add(time.Duration(slotDuration) * time.Minute)
					}
				}
			}
		}

		if err := cursor.Err(); err != nil {
			h.logger.Error("Error iterating through appointments cursor", zap.Error(err))
			// Continue with what we have instead of failing
		}
	}

	h.logger.Info("Found booked slots",
		zap.Int("booked_slot_count", len(bookedSlots)),
		zap.Strings("booked_slots", bookedSlots))

	// Filter out unavailable slots
	var availableSlots []string
	for _, slot := range allSlots {
		isAvailable := true
		for _, unavailable := range bookedSlots {
			if slot == unavailable {
				isAvailable = false
				break
			}
		}
		if isAvailable {
			availableSlots = append(availableSlots, slot)
		}
	}

	h.logger.Info("Final available slots",
		zap.Int("available_slot_count", len(availableSlots)))

	// Format the response in a structure matching the frontend expectations
	var formattedSlots []map[string]string
	for _, slot := range availableSlots {
		// Calculate end time for the slot
		startSlot, _ := time.Parse("15:04", slot)
		endSlot := startSlot.Add(time.Duration(slotDuration) * time.Minute)

		formattedSlots = append(formattedSlots, map[string]string{
			"start_time": slot,
			"end_time":   endSlot.Format("15:04"),
		})
	}

	return c.JSON(fiber.Map{
		"available_slots":   formattedSlots, // Return formatted slots with start/end times
		"raw_slots":         availableSlots, // Also include the raw slot times for compatibility
		"unavailable_slots": bookedSlots,
		"message":           "Slot availability fetched successfully",
	})
}

// GetAppointment retrieves a single appointment by ID
func (h *AppointmentHandler) GetAppointment(c *fiber.Ctx) error {
	// Get appointment ID from params
	appointmentID := c.Params("id")
	if appointmentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Appointment ID is required"})
	}

	// Validate UUID format
	if !isValidUUID(appointmentID) {
		h.logger.Error("invalid appointment ID format", zap.String("id", appointmentID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment ID format"})
	}

	// Query MongoDB for the appointment using the appointment_id field
	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")

	var appointment Appointment
	err := appointmentsCollection.FindOne(c.Context(), bson.M{"appointment_id": appointmentID}).Decode(&appointment)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Appointment not found"})
		}
		h.logger.Error("failed to fetch appointment",
			zap.Error(err),
			zap.String("appointment_id", appointmentID))
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

	nextVisitDateStr := ""
	if !appointment.NextVisitDate.IsZero() {
		nextVisitDateStr = appointment.NextVisitDate.Format(time.RFC3339)
	}

	response := AppointmentResponse{
		AppointmentID:     appointment.AppointmentID,
		PatientID:         appointment.PatientID,
		DoctorID:          appointment.DoctorID,
		OrgID:             appointment.OrgID,
		PatientName:       appointment.PatientName,
		DoctorName:        appointment.DoctorName,
		AppointmentStatus: appointment.AppointmentStatus,
		PaymentMethod:     appointment.PaymentMethod,
		FeeType:           appointment.FeeType,
		AppointmentFee:    appointment.AppointmentFee,
		AppointmentDate:   appointmentDateStr,
		CreatedAt:         appointment.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         updatedAtStr,
		IsValid:           appointment.IsValid,
		NextVisitDate:     nextVisitDateStr,
		SlotStartTime:     appointment.SlotStartTime,
		SlotEndTime:       appointment.SlotEndTime,
	}

	return c.JSON(response)
}

// isValidUUID validates if the string is a valid UUID
func isValidUUID(id string) bool {
	regex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return regex.MatchString(id)
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
	if filters.AppointmentStatus != "" {
		query["appointment_status"] = filters.AppointmentStatus
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
			OrgID:             appointment.OrgID,
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

// GetPatientByID retrieves a single patient by ID
func (h *AppointmentHandler) GetPatientByID(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get patient ID from params
	patientID := c.Params("patientID")
	if patientID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Patient ID is required"})
	}

	// Validate patient ID format
	_, err = uuid.Parse(patientID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid patient ID format"})
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

	// Only certain roles can view patient details
	if role != "admin" && role != "hospital_admin" && role != "doctor" && role != "receptionist" {
		h.logger.Error("unauthorized access attempt", zap.String("userID", userID.String()), zap.String("role", role))
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Not authorized to view patient details"})
	}

	// Query MongoDB for the patient
	patientsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("patients")
	var patient Patient
	err = patientsCollection.FindOne(c.Context(), bson.M{"patient_id": patientID}).Decode(&patient)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Patient not found"})
		}
		h.logger.Error("failed to fetch patient", zap.Error(err), zap.String("patientID", patientID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch patient"})
	}

	// Return patient data
	return c.JSON(patient)
}

// getUserOrganizations gets the user's organizations, prioritizing the X-Organization-ID header
func (h *AppointmentHandler) getUserOrganizations(ctx context.Context, userID uuid.UUID, c *fiber.Ctx) ([]string, error) {
	// First check if the organization ID was provided in the header
	if orgID := c.Get("X-Organization-ID", ""); orgID != "" {
		h.logger.Info("using organization ID from header",
			zap.String("orgID", orgID),
			zap.String("userID", userID.String()))

		// Return the organization ID from the header
		return []string{orgID}, nil
	}

	// Fall back to database lookup if no header was provided
	h.logger.Info("no organization ID in header, falling back to database",
		zap.String("userID", userID.String()))

	query := `
		SELECT organization_id 
		FROM user_organization_memberships 
		WHERE user_id = $1 AND status = 'active'
	`

	rows, err := h.pgPool.Query(ctx, query, userID)
	if err != nil {
		h.logger.Error("failed to query user organizations",
			zap.Error(err),
			zap.String("userID", userID.String()))
		return nil, fmt.Errorf("failed to query user organizations: %w", err)
	}
	defer rows.Close()

	var orgs []string
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			h.logger.Error("failed to scan organization ID",
				zap.Error(err),
				zap.String("userID", userID.String()))
			continue
		}
		orgs = append(orgs, orgID)
	}

	if err := rows.Err(); err != nil {
		h.logger.Error("error iterating organization rows",
			zap.Error(err),
			zap.String("userID", userID.String()))
		return nil, fmt.Errorf("error iterating organization rows: %w", err)
	}

	h.logger.Info("found organizations in database",
		zap.Int("count", len(orgs)),
		zap.Strings("orgIDs", orgs),
		zap.String("userID", userID.String()))

	return orgs, nil
}

// SearchDoctors searches for doctors based on various criteria - only returning doctors from the same organizations as the user
func (h *AppointmentHandler) SearchDoctors(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err), zap.String("authID", authID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve user information"})
	}

	// Log the organization ID from header for debugging
	headerOrgID := c.Get("X-Organization-ID", "")
	h.logger.Info("received request with organization header",
		zap.String("X-Organization-ID", headerOrgID),
		zap.String("userID", userID.String()))

	// Check if user role was provided in header
	userRole := c.Get("X-User-Role", "")

	// If no role was provided in the header, fall back to database lookup
	if userRole == "" {
		var dbErr error
		userRole, dbErr = h.getUserRole(c.Context(), userID)
		if dbErr != nil {
			h.logger.Error("failed to get user role", zap.Error(dbErr), zap.String("userID", userID.String()))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve user role"})
		}
	}

	// Only certain roles can search for doctors
	if userRole != "admin" && userRole != "hospital_admin" && userRole != "doctor" && userRole != "frontdesk" {
		h.logger.Error("unauthorized access attempt", zap.String("userID", userID.String()), zap.String("role", userRole))
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Not authorized to search doctors"})
	}

	// Get search parameters
	searchQuery := c.Query("q", "")
	searchBy := c.Query("by", "name") // default search by name
	speciality := c.Query("speciality", "")
	organizationID := c.Query("organization_id", "")

	// Use the updated function which checks for organization ID in header first
	userOrgs, err := h.getUserOrganizations(c.Context(), userID, c)
	if err != nil {
		h.logger.Error("failed to get user organizations", zap.Error(err), zap.String("userID", userID.String()))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve user organizations"})
	}

	// Debug log to see what organizations we found
	h.logger.Info("organizations found for user",
		zap.Strings("organizations", userOrgs),
		zap.String("userID", userID.String()))

	if len(userOrgs) == 0 {
		h.logger.Error("user has no organizations", zap.String("userID", userID.String()))
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "User is not part of any organization"})
	}

	// Check if the requested organization ID is in the user's organizations
	if organizationID != "" {
		validOrg := false
		for _, org := range userOrgs {
			if org == organizationID {
				validOrg = true
				break
			}
		}
		if !validOrg {
			h.logger.Error("user attempted to access unauthorized organization",
				zap.String("userID", userID.String()),
				zap.String("requestedOrgID", organizationID))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Not authorized to access this organization"})
		}
	}

	// Parse pagination parameters
	limit, err := strconv.Atoi(c.Query("limit", "20"))
	if err != nil || limit <= 0 {
		limit = 20 // Default limit
	}
	if limit > 100 {
		limit = 100 // Maximum limit
	}

	offset, err := strconv.Atoi(c.Query("offset", "0"))
	if err != nil || offset < 0 {
		offset = 0 // Default offset
	}

	// FIXED QUERY: The doctor_id in doctors table is the same as user_id in users table
	// We need to join to user_organization_memberships using this ID
	baseQuery := `
		SELECT DISTINCT d.doctor_id, d.name, d.specialization, d.age,
			d.qualification, d.imr_number, d.is_active, 
			d.slot_duration, uom.organization_id
		FROM doctors d
		JOIN user_organization_memberships uom ON d.doctor_id = uom.user_id
		WHERE uom.organization_id IN (`

	// Build the count query with the same fix
	countQuery := `
		SELECT COUNT(DISTINCT d.doctor_id)
		FROM doctors d
		JOIN user_organization_memberships uom ON d.doctor_id = uom.user_id
		WHERE uom.organization_id IN (`

	// Initialize query parameters
	queryParams := []interface{}{}
	paramCount := 1

	// Add organization parameters
	orgPlaceholders := []string{}
	if organizationID != "" {
		orgPlaceholders = append(orgPlaceholders, fmt.Sprintf("$%d", paramCount))
		queryParams = append(queryParams, organizationID)
		paramCount++
	} else {
		// Add all user organizations to the query
		for _, org := range userOrgs {
			orgPlaceholders = append(orgPlaceholders, fmt.Sprintf("$%d", paramCount))
			queryParams = append(queryParams, org)
			paramCount++
		}
	}

	// Complete the base queries with organization placeholders
	baseQuery += strings.Join(orgPlaceholders, ", ") + ") "
	countQuery += strings.Join(orgPlaceholders, ", ") + ") "

	// Log what we're searching for (debugging)
	h.logger.Info("search parameters",
		zap.String("userID", userID.String()),
		zap.Strings("organization_placeholders", orgPlaceholders),
		zap.Any("query_params", queryParams))

	// Add search conditions based on searchBy parameter
	if searchQuery != "" {
		switch searchBy {
		case "name":
			baseQuery += fmt.Sprintf(" AND d.name ILIKE $%d", paramCount)
			countQuery += fmt.Sprintf(" AND d.name ILIKE $%d", paramCount)
			queryParams = append(queryParams, "%"+searchQuery+"%")
			paramCount++
		case "license": // Using imr_number instead of license_number
			baseQuery += fmt.Sprintf(" AND d.imr_number ILIKE $%d", paramCount)
			countQuery += fmt.Sprintf(" AND d.imr_number ILIKE $%d", paramCount)
			queryParams = append(queryParams, "%"+searchQuery+"%")
			paramCount++
		case "qualification":
			baseQuery += fmt.Sprintf(" AND d.qualification ILIKE $%d", paramCount)
			countQuery += fmt.Sprintf(" AND d.qualification ILIKE $%d", paramCount)
			queryParams = append(queryParams, "%"+searchQuery+"%")
			paramCount++
		case "all":
			baseQuery += fmt.Sprintf(` AND (
					d.name ILIKE $%d OR 
					d.imr_number ILIKE $%d OR 
					d.qualification ILIKE $%d OR
					d.specialization::text ILIKE $%d)`,
				paramCount, paramCount, paramCount, paramCount)
			countQuery += fmt.Sprintf(` AND (
					d.name ILIKE $%d OR 
					d.imr_number ILIKE $%d OR 
					d.qualification ILIKE $%d OR
					d.specialization::text ILIKE $%d)`,
				paramCount, paramCount, paramCount, paramCount)
			queryParams = append(queryParams, "%"+searchQuery+"%")
			paramCount++
		}
	}

	// Add speciality filter if provided - note that specialization is JSONB
	if speciality != "" {
		baseQuery += fmt.Sprintf(" AND d.specialization::text ILIKE $%d", paramCount)
		countQuery += fmt.Sprintf(" AND d.specialization::text ILIKE $%d", paramCount)
		queryParams = append(queryParams, "%"+speciality+"%")
		paramCount++
	}

	// Remove the active status filter since most doctors have is_active = false
	// If you still want to filter by active status, you can uncomment these lines
	// baseQuery += " AND d.is_active = true"
	// countQuery += " AND d.is_active = true"

	// Log final queries for debugging
	h.logger.Info("executing queries",
		zap.String("baseQuery", baseQuery),
		zap.String("countQuery", countQuery))

	// Add pagination and ordering
	baseQuery += " ORDER BY d.name"
	baseQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", paramCount, paramCount+1)
	queryParams = append(queryParams, limit, offset)

	// Query for total count
	var total int
	err = h.pgPool.QueryRow(c.Context(), countQuery, queryParams[:paramCount-1]...).Scan(&total)
	if err != nil {
		h.logger.Error("failed to count doctors", zap.Error(err))
		// Continue with the results but without total count
		total = 0
	}

	// Log count results
	h.logger.Info("count query result", zap.Int("total", total))

	// Execute the main query
	rows, err := h.pgPool.Query(c.Context(), baseQuery, queryParams...)
	if err != nil {
		h.logger.Error("failed to query doctors", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to search doctors"})
	}
	defer rows.Close()

	// Process doctors
	var doctors []DoctorSearchResult
	for rows.Next() {
		var doctor DoctorSearchResult
		var specializationJSON []byte
		var organizationID sql.NullString
		var slotDuration sql.NullInt32
		var isActive bool

		if err := rows.Scan(
			&doctor.DoctorID,
			&doctor.Name,
			&specializationJSON,
			&doctor.Age,
			&doctor.Qualification,
			&doctor.IMRNumber,
			&isActive,
			&slotDuration,
			&organizationID,
		); err != nil {
			h.logger.Error("failed to scan doctor row", zap.Error(err))
			continue
		}

		// Handle nullable organization fields
		if organizationID.Valid {
			doctor.OrganizationID = organizationID.String
		}

		// Handle nullable slot duration
		if slotDuration.Valid {
			doctor.SlotDuration = int(slotDuration.Int32)
		}

		// Set active status
		doctor.IsActive = isActive

		// Parse specialization from JSON
		if len(specializationJSON) > 0 {
			// Depending on your JSON structure, adjust the parsing
			var specializations map[string]interface{}
			if err := json.Unmarshal(specializationJSON, &specializations); err != nil {
				// Try as array if map fails
				var specializationArray []string
				if err := json.Unmarshal(specializationJSON, &specializationArray); err != nil {
					h.logger.Error("failed to parse specialization JSON", zap.Error(err))
				} else if len(specializationArray) > 0 {
					doctor.Speciality = strings.Join(specializationArray, ", ")
				}
			} else {
				// Extract primary specialization if it exists
				if primary, ok := specializations["primary"].(string); ok {
					doctor.Speciality = primary
					// Add secondary if it exists
					if secondary, ok := specializations["secondary"].(string); ok {
						doctor.Speciality += ", " + secondary
					}
				}
			}
		}

		// Add to results
		doctors = append(doctors, doctor)
	}

	if err := rows.Err(); err != nil {
		h.logger.Error("cursor error", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error processing doctors"})
	}

	// Log success and result count
	h.logger.Info("search completed successfully",
		zap.Int("total_doctors", len(doctors)),
		zap.String("userID", userID.String()))

	return c.JSON(fiber.Map{
		"doctors": doctors,
		"pagination": fiber.Map{
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

func (h *AppointmentHandler) CreatePatient(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	fmt.Println(userID)
	// Parse patient data from request body
	var patientRequest struct {
		Name             string     `json:"name"`
		Email            string     `json:"email"`
		Mobile           string     `json:"mobile"`
		Gender           string     `json:"gender,omitempty"`
		Age              int        `json:"age,omitempty"`
		BloodGroup       string     `json:"blood_group,omitempty"`
		Address          string     `json:"address,omitempty"`
		AadhaarID        string     `json:"aadhaar_id,omitempty"`
		MedicalHistory   []Medical  `json:"medical_history,omitempty"`
		Allergies        []string   `json:"allergies,omitempty"`
		EmergencyContact *Contact   `json:"emergency_contact,omitempty"`
		Insurance        *Insurance `json:"insurance,omitempty"`
		HospitalVisits   []Visit    `json:"hospital_visits,omitempty"`
	}

	if err := c.BodyParser(&patientRequest); err != nil {
		h.logger.Error("failed to parse patient data", zap.Error(err))
		// Log the request body for debugging
		h.logger.Debug("request body", zap.String("body", string(c.Body())))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid patient data: " + err.Error()})
	}

	// Log the parsed request for debugging
	requestJSON, _ := json.Marshal(patientRequest)
	h.logger.Debug("parsed patient request", zap.String("request", string(requestJSON)))

	// Validate required fields based on schema
	if patientRequest.Name == "" || patientRequest.Email == "" || patientRequest.Mobile == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields: name, email, and mobile are required"})
	}

	// Validate email format
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(patientRequest.Email) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid email format"})
	}

	// Validate blood group format if provided
	if patientRequest.BloodGroup != "" {
		bloodGroupRegex := regexp.MustCompile(`^(A|B|AB|O)[+-]$`)
		if !bloodGroupRegex.MatchString(patientRequest.BloodGroup) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid blood group format, must be A+, A-, B+, B-, AB+, AB-, O+, or O-"})
		}
	}

	// Validate Aadhaar ID if provided
	if patientRequest.AadhaarID != "" {
		aadhaarRegex := regexp.MustCompile(`^\d{12}$`)
		if !aadhaarRegex.MatchString(patientRequest.AadhaarID) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid Aadhaar ID format, must be 12 digits"})
		}
	}

	// Generate unique 8-digit patient ID
	patientID, err := h.generateUniquePatientID(c.Context())
	if err != nil {
		h.logger.Error("failed to generate patient ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate patient ID"})
	}

	// Create patient document with proper bson field names
	patient := Patient{
		PatientID:        patientID,
		Name:             patientRequest.Name,
		Email:            patientRequest.Email,
		Mobile:           patientRequest.Mobile,
		Gender:           patientRequest.Gender,
		Age:              patientRequest.Age,
		BloodGroup:       patientRequest.BloodGroup,
		Address:          patientRequest.Address,
		AadhaarID:        patientRequest.AadhaarID,
		MedicalHistory:   patientRequest.MedicalHistory,
		Allergies:        patientRequest.Allergies,
		EmergencyContact: patientRequest.EmergencyContact,
		Insurance:        patientRequest.Insurance,
		HospitalVisits:   patientRequest.HospitalVisits,
		AuthID:           authID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Convert to BSON document to ensure proper field names
	patientBSON, err := bson.Marshal(patient)
	if err != nil {
		h.logger.Error("failed to convert patient to BSON", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process patient data"})
	}

	var patientDoc bson.D
	if err := bson.Unmarshal(patientBSON, &patientDoc); err != nil {
		h.logger.Error("failed to unmarshal patient BSON", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process patient data"})
	}

	// Insert patient into MongoDB
	patientsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("patients")

	// First, do the insertion
	result, err := patientsCollection.InsertOne(c.Context(), patientDoc)
	if err != nil {
		// Log detailed error
		h.logger.Error("failed to insert patient", zap.Error(err))

		// Convert patient to JSON for debugging
		patientJSON, _ := json.Marshal(patient)
		h.logger.Debug("patient data being inserted", zap.String("patient_json", string(patientJSON)))

		// Get validation errors if available
		if cmdErr, ok := err.(mongo.CommandError); ok {
			h.logger.Error("MongoDB command error", zap.String("error_name", cmdErr.Name), zap.String("error_message", cmdErr.Message))
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create patient: " + err.Error()})
	}

	// Then, optionally verify the insertion if needed
	var insertedPatient Patient
	findErr := patientsCollection.FindOne(c.Context(), bson.M{"patient_id": patientID}).Decode(&insertedPatient)
	if findErr != nil {
		h.logger.Error("verification failed - patient not found after insertion", zap.Error(findErr), zap.String("patient_id", patientID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Patient creation verification failed"})
	}

	h.logger.Info("patient created successfully", zap.String("patient_id", patientID), zap.Any("mongo_id", result.InsertedID))

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Patient created successfully",
		"patient": patient,
	})
}

// Helper function to generate a unique 8-digit alphanumeric patient ID
func (h *AppointmentHandler) generateUniquePatientID(ctx context.Context) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const idLength = 8

	for attempts := 0; attempts < 10; attempts++ {
		// Generate random ID
		b := make([]byte, idLength)
		for i := range b {
			b[i] = charset[rand.Intn(len(charset))]
		}
		patientID := string(b)

		// Check if ID already exists
		patientsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("patients")
		count, err := patientsCollection.CountDocuments(ctx, bson.M{"patient_id": patientID})
		if err != nil {
			return "", err
		}

		if count == 0 {
			return patientID, nil
		}
	}

	return "", errors.New("failed to generate unique patient ID after multiple attempts")
}

func (h *AppointmentHandler) GetPatient(c *fiber.Ctx) error {
	// Get patient ID from URL parameter
	patientID := c.Params("id")
	if patientID == "" {
		h.logger.Error("patient ID is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Patient ID is required"})
	}

	h.logger.Info("fetching patient", zap.String("patientID", patientID))

	// Access patients collection
	dbName := h.config.MongoDBName
	collectionName := "patients"
	patientsCollection := h.mongoClient.Database(dbName).Collection(collectionName)

	// Log the database and collection being queried
	h.logger.Debug("accessing database collection",
		zap.String("database", dbName),
		zap.String("collection", collectionName))

	// Create filter
	filter := bson.M{"patient_id": patientID}
	h.logger.Debug("query filter", zap.Any("filter", filter))

	// Try to find the patient
	var patient Patient
	h.logger.Debug("executing database query")

	// Execute the query with a timeout context
	ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
	defer cancel()

	err := patientsCollection.FindOne(ctx, filter).Decode(&patient)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			h.logger.Error("patient not found",
				zap.String("patientID", patientID),
				zap.String("errorType", "document_not_found"))

			// Check if any patients exist in the collection
			count, countErr := patientsCollection.CountDocuments(ctx, bson.M{})
			if countErr == nil {
				h.logger.Info("total patients in collection", zap.Int64("count", count))
			} else {
				h.logger.Error("failed to count documents", zap.Error(countErr))
			}

			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Patient not found",
				"id":    patientID,
			})
		}

		h.logger.Error("failed to fetch patient",
			zap.String("patientID", patientID),
			zap.Error(err),
			zap.String("errorType", "database_error"))

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch patient",
		})
	}

	h.logger.Info("patient retrieved successfully",
		zap.String("patientID", patientID),
		zap.String("name", patient.Name))

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Patient retrieved successfully",
		"patient": patient,
	})
}

func (h *AppointmentHandler) PatientHandler(c *fiber.Ctx) error {
	// Get patient ID from URL parameter
	patientID := c.Params("id")
	if patientID == "" {
		h.logger.Error("patient ID is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Patient ID is required"})
	}

	// Access patients collection
	patientsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("patients")

	// Handle different HTTP methods
	switch c.Method() {
	case "GET":
		// Find patient document using only patient_id for retrieval
		var patient Patient
		filter := bson.M{"patient_id": patientID}
		err := patientsCollection.FindOne(c.Context(), filter).Decode(&patient)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				h.logger.Error("patient not found", zap.String("patientID", patientID))
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Patient not found"})
			}
			h.logger.Error("failed to fetch patient", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch patient"})
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Patient retrieved successfully",
			"patient": patient,
		})

	case "PUT":
		// Parse the update data
		var updateData map[string]interface{}
		if err := c.BodyParser(&updateData); err != nil {
			h.logger.Error("failed to parse request body", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
		}

		// Add updated_at timestamp
		updateData["updated_at"] = time.Now()

		// Remove any user_id if it exists in updateData
		delete(updateData, "user_id")

		// Create update document
		update := bson.M{"$set": updateData}

		// Update the patient using only the patient_id
		filter := bson.M{"patient_id": patientID}
		result, err := patientsCollection.UpdateOne(c.Context(), filter, update)
		if err != nil {
			h.logger.Error("failed to update patient", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update patient"})
		}
		if result.MatchedCount == 0 {
			// If no document was found, try to insert a new one with this ID
			updateData["patient_id"] = patientID
			updateData["created_at"] = time.Now()

			_, err := patientsCollection.InsertOne(c.Context(), updateData)
			if err != nil {
				h.logger.Error("failed to create patient on update", zap.Error(err))
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Patient not found and failed to create"})
			}

			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"message":    "Patient created successfully",
				"patient_id": patientID,
			})
		}

		// Get updated patient data
		var updatedPatient Patient
		err = patientsCollection.FindOne(c.Context(), filter).Decode(&updatedPatient)
		if err != nil {
			h.logger.Error("failed to fetch updated patient", zap.Error(err))
			// Still return success since update was successful
			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"message": "Patient updated successfully",
			})
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Patient updated successfully",
			"patient": updatedPatient,
		})

	case "POST":
		// Parse the patient data
		var patientData map[string]interface{}
		if err := c.BodyParser(&patientData); err != nil {
			h.logger.Error("failed to parse request body", zap.Error(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
		}

		// Remove any user_id if it exists in patientData
		delete(patientData, "user_id")

		// Ensure the patient_id in the body matches the URL parameter
		patientData["patient_id"] = patientID
		patientData["created_at"] = time.Now()
		patientData["updated_at"] = time.Now()

		// Check if patient already exists
		var existingPatient Patient
		filter := bson.M{"patient_id": patientID}
		err := patientsCollection.FindOne(c.Context(), filter).Decode(&existingPatient)
		if err == nil {
			// Patient already exists, update instead
			update := bson.M{"$set": patientData}
			_, err = patientsCollection.UpdateOne(c.Context(), filter, update)
			if err != nil {
				h.logger.Error("failed to update existing patient", zap.Error(err))
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update existing patient"})
			}
			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"message":    "Patient updated successfully",
				"patient_id": patientID,
			})
		}

		// Insert new patient
		_, err = patientsCollection.InsertOne(c.Context(), patientData)
		if err != nil {
			h.logger.Error("failed to create patient", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create patient"})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message":    "Patient created successfully",
			"patient_id": patientID,
		})

	case "DELETE":
		// Delete patient using only patient_id
		filter := bson.M{"patient_id": patientID}
		result, err := patientsCollection.DeleteOne(c.Context(), filter)
		if err != nil {
			h.logger.Error("failed to delete patient", zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete patient"})
		}
		if result.DeletedCount == 0 {
			h.logger.Error("patient not found for deletion", zap.String("patientID", patientID))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Patient not found"})
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Patient deleted successfully",
		})

	default:
		return c.Status(fiber.StatusMethodNotAllowed).JSON(fiber.Map{"error": "Method not allowed"})
	}
}

func (h *AppointmentHandler) GetAllPatients(c *fiber.Ctx) error {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.Query("page", "1"))
	limit, _ := strconv.Atoi(c.Query("limit", "10"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10 // Default limit and also max limit
	}
	skip := (page - 1) * limit

	// Set up an empty filter to get all patients
	filter := bson.M{}

	// Add search capability if provided
	search := c.Query("search")
	if search != "" {
		// Create a text search query
		filter["$or"] = []bson.M{
			{"name": bson.M{"$regex": search, "$options": "i"}},
			{"email": bson.M{"$regex": search, "$options": "i"}},
			{"mobile": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	// Add blood group filter if provided
	bloodGroup := c.Query("bloodGroup")
	if bloodGroup != "" {
		filter["blood_group"] = bloodGroup
	}

	// Access patients collection
	patientsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("patients")

	// Count total patients matching the filter
	total, err := patientsCollection.CountDocuments(c.Context(), filter)
	if err != nil {
		h.logger.Error("failed to count patients", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to count patients"})
	}

	// Create options for sorting and pagination
	findOptions := options.Find().
		SetSort(bson.M{"created_at": -1}). // Sort by created_at descending (newest first)
		SetSkip(int64(skip)).
		SetLimit(int64(limit))

	// Find patients with pagination
	cursor, err := patientsCollection.Find(c.Context(), filter, findOptions)
	if err != nil {
		h.logger.Error("failed to fetch patients", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch patients"})
	}
	defer cursor.Close(c.Context())

	// Decode the patients
	var patients []Patient
	if err = cursor.All(c.Context(), &patients); err != nil {
		h.logger.Error("failed to decode patients", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode patients"})
	}

	// Return paginated result with metadata
	return c.JSON(fiber.Map{
		"data":       patients,
		"page":       page,
		"limit":      limit,
		"total":      total,
		"totalPages": int(math.Ceil(float64(total) / float64(limit))),
	})
}

// SearchPatients searches for patients with more advanced filtering
func (h *AppointmentHandler) SearchPatients(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Parse query parameters
	query := c.Query("query", "")
	limit, _ := strconv.Atoi(c.Query("limit", "10"))
	if limit < 1 || limit > 50 {
		limit = 10 // Default and max limit
	}

	// Prepare filter
	filter := bson.M{"user_id": userID.String()}

	// Add search query
	if query != "" {
		filter["$or"] = []bson.M{
			{"name": bson.M{"$regex": query, "$options": "i"}},
			{"email": bson.M{"$regex": query, "$options": "i"}},
			{"mobile": bson.M{"$regex": query, "$options": "i"}},
		}
	}

	// Add blood group filter if provided
	bloodGroup := c.Query("bloodGroup")
	if bloodGroup != "" {
		filter["blood_group"] = bloodGroup
	}

	// Add age filter if provided
	age := c.Query("age")
	if age != "" {
		ageInt, err := strconv.Atoi(age)
		if err == nil {
			filter["age"] = ageInt
		}
	}

	// Access patients collection
	patientsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("patients")

	// Find patients
	findOptions := options.Find().
		SetSort(bson.M{"name": 1}). // Sort by name
		SetLimit(int64(limit))

	cursor, err := patientsCollection.Find(c.Context(), filter, findOptions)
	if err != nil {
		h.logger.Error("failed to search patients", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to search patients"})
	}
	defer cursor.Close(c.Context())

	// Decode the patients
	var patients []Patient
	if err = cursor.All(c.Context(), &patients); err != nil {
		h.logger.Error("failed to decode patients", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode patients"})
	}

	return c.JSON(fiber.Map{
		"data":  patients,
		"count": len(patients),
	})
}

// UpdatePatient updates a patient record by ID
func (h *AppointmentHandler) UpdatePatient(c *fiber.Ctx) error {
	// Get patient ID from URL parameter
	patientID := c.Params("id")
	if patientID == "" {
		h.logger.Error("patient ID is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Patient ID is required"})
	}

	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Parse update data from request body
	var updateRequest struct {
		Name       string   `json:"name,omitempty"`
		Email      string   `json:"email,omitempty"`
		Mobile     string   `json:"mobile,omitempty"`
		Age        int      `json:"age,omitempty"`
		BloodGroup string   `json:"blood_group,omitempty"`
		Address    string   `json:"address,omitempty"`
		AadhaarID  string   `json:"aadhaar_id,omitempty"`
		Allergies  []string `json:"allergies,omitempty"`
	}

	if err := c.BodyParser(&updateRequest); err != nil {
		h.logger.Error("failed to parse update data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid update data"})
	}

	// Validate email format if provided
	if updateRequest.Email != "" {
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		if !emailRegex.MatchString(updateRequest.Email) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid email format"})
		}
	}

	// Validate blood group format if provided
	if updateRequest.BloodGroup != "" {
		bloodGroupRegex := regexp.MustCompile(`^(A|B|AB|O)[+-]$`)
		if !bloodGroupRegex.MatchString(updateRequest.BloodGroup) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid blood group format"})
		}
	}

	// Validate Aadhaar ID format if provided
	if updateRequest.AadhaarID != "" {
		aadhaarRegex := regexp.MustCompile(`^\d{12}$`)
		if !aadhaarRegex.MatchString(updateRequest.AadhaarID) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid Aadhaar ID format"})
		}
	}

	// Access patients collection
	patientsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("patients")

	// Create update document
	update := bson.M{"updated_at": time.Now()}

	if updateRequest.Name != "" {
		update["name"] = updateRequest.Name
	}
	if updateRequest.Email != "" {
		update["email"] = updateRequest.Email
	}
	if updateRequest.Mobile != "" {
		update["mobile"] = updateRequest.Mobile
	}
	if updateRequest.Age != 0 {
		update["age"] = updateRequest.Age
	}
	if updateRequest.BloodGroup != "" {
		update["blood_group"] = updateRequest.BloodGroup
	}
	if updateRequest.Address != "" {
		update["address"] = updateRequest.Address
	}
	if updateRequest.AadhaarID != "" {
		update["aadhaar_id"] = updateRequest.AadhaarID
	}
	if len(updateRequest.Allergies) > 0 {
		update["allergies"] = updateRequest.Allergies
	}

	// Update patient document
	filter := bson.M{"patient_id": patientID, "user_id": userID.String()}
	result, err := patientsCollection.UpdateOne(
		c.Context(),
		filter,
		bson.M{"$set": update},
	)

	if err != nil {
		h.logger.Error("failed to update patient", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update patient"})
	}

	if result.MatchedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Patient not found"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Patient updated successfully",
	})
}

// DeletePatient deletes a patient record by ID
func (h *AppointmentHandler) DeletePatient(c *fiber.Ctx) error {
	// Get patient ID from URL parameter
	patientID := c.Params("id")
	if patientID == "" {
		h.logger.Error("patient ID is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Patient ID is required"})
	}

	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Get user ID
	userID, err := h.getUserID(c.Context(), authID)
	if err != nil {
		h.logger.Error("failed to get user ID", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// Access patients collection
	patientsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("patients")

	// Delete the patient document
	filter := bson.M{"patient_id": patientID, "user_id": userID.String()}
	result, err := patientsCollection.DeleteOne(c.Context(), filter)

	if err != nil {
		h.logger.Error("failed to delete patient", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete patient"})
	}

	if result.DeletedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Patient not found"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Patient deleted successfully",
	})
}
