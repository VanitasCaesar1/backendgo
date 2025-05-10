package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
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

type Appointment struct {
	PatientID         string    `json:"patient_id" bson:"patient_id"`
	DoctorID          string    `json:"doctor_id" bson:"doctor_id"`
	OrgID             string    `json:"org_id" bson:"org_id"`
	PatientName       string    `json:"patient_name" bson:"patient_name"`
	DoctorName        string    `json:"doctor_name" bson:"doctor_name"`
	AppointmentStatus string    `json:"appointment_status" bson:"appointment_status"`
	PaymentMethod     string    `json:"payment_method" bson:"payment_method"`
	FeeType           string    `json:"fee_type" bson:"fee_type"`
	AppointmentFee    int       `json:"appointment_fee" bson:"appointment_fee"` // Changed to int to match schema
	AppointmentDate   time.Time `json:"appointment_date" bson:"appointment_date"`
	CreatedAt         time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" bson:"updated_at"`
	Reason            string    `json:"reason,omitempty" bson:"reason,omitempty"` // Optional field
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
			HospitalID:        appointment.OrgID,
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

func (h *AppointmentHandler) CreateAppointment(c *fiber.Ctx) error {
	// Get auth ID from context
	authID, err := h.getAuthID(c)
	if err != nil {
		h.logger.Error("authID not found in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Parse appointment data from request body
	var appointmentRequest struct {
		PatientID       string    `json:"patient_id"`
		DoctorID        string    `json:"doctor_id"`
		OrgID           string    `json:"org_id"`       // Changed from HospitalID to OrgID
		PatientName     string    `json:"patient_name"` // Changed to snake_case to match schema
		DoctorName      string    `json:"doctor_name"`  // Changed to snake_case to match schema
		AppointmentDate time.Time `json:"appointment_date"`
		FeeType         string    `json:"fee_type"`         // Changed to snake_case
		PaymentMethod   string    `json:"payment_method"`   // Changed to snake_case
		Reason          string    `json:"reason,omitempty"` // Optional field
	}

	if err := c.BodyParser(&appointmentRequest); err != nil {
		h.logger.Error("failed to parse appointment data", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid appointment data"})
	}

	// Validate required fields
	if appointmentRequest.PatientID == "" || appointmentRequest.DoctorID == "" || appointmentRequest.OrgID == "" ||
		appointmentRequest.PatientName == "" || appointmentRequest.DoctorName == "" ||
		appointmentRequest.AppointmentDate.IsZero() || appointmentRequest.FeeType == "" || appointmentRequest.PaymentMethod == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
	}

	// Validate ID formats based on schema requirements
	if !validatePatientID(appointmentRequest.PatientID) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Patient ID must be 8-digit alphanumeric format"})
	}

	if !validateDoctorID(appointmentRequest.DoctorID) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor ID must be in UUID format"})
	}

	if !validateOrgID(appointmentRequest.OrgID) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Organization ID must be in ULID format (org_[A-Z0-9]{26})"})
	}

	// Validate fee type
	if appointmentRequest.FeeType != "emergency" && appointmentRequest.FeeType != "default" && appointmentRequest.FeeType != "recurring" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Fee type must be emergency, default, or recurring"})
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

	// Verify doctor availability for the selected time slot
	if !h.isDoctorAvailable(c.Context(), appointmentRequest.DoctorID, appointmentRequest.OrgID, appointmentRequest.AppointmentDate) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Doctor is not available at selected time"})
	}

	// Get doctor's fees based on fee type
	appointmentFee, err := h.getDoctorFee(c.Context(), appointmentRequest.DoctorID, appointmentRequest.OrgID, appointmentRequest.FeeType)
	if err != nil {
		h.logger.Error("failed to get doctor fees", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get doctor fees"})
	}

	// Create appointment document (using field names that match the schema)
	now := time.Now()
	appointment := Appointment{
		PatientID:         appointmentRequest.PatientID,
		DoctorID:          appointmentRequest.DoctorID,
		OrgID:             appointmentRequest.OrgID, // Changed from HospitalID
		PatientName:       appointmentRequest.PatientName,
		DoctorName:        appointmentRequest.DoctorName,
		AppointmentStatus: "not_completed", // Default value that matches schema enum
		PaymentMethod:     appointmentRequest.PaymentMethod,
		FeeType:           appointmentRequest.FeeType,
		AppointmentFee:    appointmentFee,
		AppointmentDate:   appointmentRequest.AppointmentDate,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

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

// Helper functions to validate ID formats
func validatePatientID(id string) bool {
	// 8-digit alphanumeric format validation
	match, _ := regexp.MatchString("^[A-Z0-9]{8}$", id)
	return match
}

func validateDoctorID(id string) bool {
	// UUID format validation
	match, _ := regexp.MatchString("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id)
	return match
}

func validateOrgID(id string) bool {
	// ULID format with org_ prefix validation
	match, _ := regexp.MatchString("^org_[A-Z0-9]{26}$", id)
	return match
}

// Helper method to check doctor availability
func (h *AppointmentHandler) isDoctorAvailable(ctx context.Context, doctorID, hospitalID string, appointmentTime time.Time) bool {
	// Get the weekday of the appointment
	weekday := strings.ToLower(appointmentTime.Weekday().String())

	// Check doctor's shift for that day
	var shift struct {
		StartTime string `json:"starttime"`
		EndTime   string `json:"endtime"`
		IsActive  bool   `json:"isactive"`
	}

	// Query PostgreSQL for doctor shift info
	err := h.pgPool.QueryRow(ctx,
		"SELECT starttime, endtime, isactive FROM public.doctorshifts WHERE doctor_id = $1 AND hospital_id = $2 AND weekday = $3",
		doctorID, hospitalID, weekday).Scan(&shift.StartTime, &shift.EndTime, &shift.IsActive)

	if err != nil {
		h.logger.Error("failed to get doctor shift", zap.Error(err))
		return false
	}

	// Check if the doctor is active for this shift
	if !shift.IsActive {
		return false
	}

	// Parse shift times
	startTime, err := time.Parse("15:04:05", shift.StartTime)
	if err != nil {
		h.logger.Error("failed to parse shift start time", zap.Error(err))
		return false
	}

	endTime, err := time.Parse("15:04:05", shift.EndTime)
	if err != nil {
		h.logger.Error("failed to parse shift end time", zap.Error(err))
		return false
	}

	// Extract appointment hour and minute
	appointmentTimeOnly := time.Date(2000, 1, 1, appointmentTime.Hour(), appointmentTime.Minute(), 0, 0, time.UTC)

	// Check if appointment time is within shift
	isWithinShift := !appointmentTimeOnly.Before(startTime) && !appointmentTimeOnly.After(endTime)
	if !isWithinShift {
		return false
	}

	// Check for existing appointments at the same time
	var count int64
	filter := bson.M{
		"doctor_id":   doctorID,
		"hospital_id": hospitalID,
		"appointment_date": bson.M{
			"$gte": appointmentTime,
			"$lt":  appointmentTime.Add(30 * time.Minute), // Assuming 30-min slots
		},
	}

	appointmentsCollection := h.mongoClient.Database(h.config.MongoDBName).Collection("appointments")
	count, err = appointmentsCollection.CountDocuments(ctx, filter)
	if err != nil {
		h.logger.Error("failed to check existing appointments", zap.Error(err))
		return false
	}

	// If count > 0, there's an overlapping appointment
	return count == 0
}

// Helper method to get doctor fee based on fee type
func (h *AppointmentHandler) getDoctorFee(ctx context.Context, doctorID, hospitalID, feeType string) (int, error) {
	var fee int

	query := "SELECT "
	switch feeType {
	case "emergency":
		query += "emergency_fees"
	case "recurring":
		query += "recurring_fees"
	default:
		query += "default_fees"
	}

	query += " FROM public.doctor_fees WHERE doctor_id = $1 AND hospital_id = $2"

	err := h.pgPool.QueryRow(ctx, query, doctorID, hospitalID).Scan(&fee)
	if err != nil {
		return 0, err
	}

	return fee, nil
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
		HospitalID:        appointment.OrgID,
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
			HospitalID:        appointment.OrgID,
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
