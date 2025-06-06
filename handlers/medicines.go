package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.uber.org/zap"
)

// Medicine represents the medicine data structure
type Medicine struct {
	ID      int    `json:"id"`
	Code    string `json:"code"`
	Name    string `json:"name"`
	Unit    string `json:"unit"`
	Company string `json:"company"`
}

// MedicineHandler handles medicine-related requests
type MedicineHandler struct {
	config      *config.Config
	redisClient *redis.Client
	logger      *zap.Logger
	pgPool      *pgxpool.Pool
	mongoClient *mongo.Client
}

// NewMedicineHandler creates a new MedicineHandler
func NewMedicineHandler(pgPool *pgxpool.Pool, logger *zap.Logger, cfg *config.Config, rds *redis.Client, mongoClient *mongo.Client) *MedicineHandler {
	return &MedicineHandler{
		config:      cfg,
		redisClient: rds,
		logger:      logger,
		pgPool:      pgPool,
		mongoClient: mongoClient,
	}
}

// SearchMedicines searches for medicines based on the provided search term
func (h *MedicineHandler) SearchMedicines(c *fiber.Ctx) error {
	// Get search term from query parameter
	searchTerm := c.Query("term")
	if searchTerm == "" {
		h.logger.Error("search term is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Search term is required"})
	}
	h.logger.Info("searching medicines", zap.String("searchTerm", searchTerm))

	// Create context with timeout
	ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
	defer cancel()

	// Prepare the SQL query with COALESCE to handle NULL values
	query := `
		SELECT id, 
		       COALESCE(code, '') as code,
		       COALESCE(name, '') as name, 
		       COALESCE(unit, '') as unit,
		       COALESCE(company, '') as company
		FROM public.medicines
		WHERE
			COALESCE(name, '') ILIKE $1 OR
			COALESCE(code, '') ILIKE $1 OR
			COALESCE(company, '') ILIKE $1
		ORDER BY name ASC
		LIMIT 50
	`

	// Add wildcard pattern for LIKE search
	pattern := fmt.Sprintf("%%%s%%", searchTerm)
	h.logger.Debug("executing database query",
		zap.String("query", query),
		zap.String("pattern", pattern))

	// Execute the query
	rows, err := h.pgPool.Query(ctx, query, pattern)
	if err != nil {
		h.logger.Error("failed to search medicines",
			zap.String("searchTerm", searchTerm),
			zap.Error(err),
			zap.String("errorType", "database_error"))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to search medicines",
		})
	}
	defer rows.Close()

	// Parse the results
	var medicines []Medicine
	for rows.Next() {
		var med Medicine
		// Now scanning should work since COALESCE ensures no NULL values
		if err := rows.Scan(&med.ID, &med.Code, &med.Name, &med.Unit, &med.Company); err != nil {
			h.logger.Error("failed to scan medicine row",
				zap.Error(err),
				zap.String("errorType", "row_scan_error"))
			continue
		}
		medicines = append(medicines, med)
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		h.logger.Error("error during row iteration",
			zap.Error(err),
			zap.String("errorType", "row_iteration_error"))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error while processing search results",
		})
	}

	// Check if no medicines were found
	if len(medicines) == 0 {
		h.logger.Info("no medicines found matching search term",
			zap.String("searchTerm", searchTerm))
		// Get total count of medicines for debugging
		var count int
		countErr := h.pgPool.QueryRow(ctx, "SELECT COUNT(*) FROM public.medicines").Scan(&count)
		if countErr == nil {
			h.logger.Info("total medicines in table", zap.Int("count", count))
		} else {
			h.logger.Error("failed to count medicines", zap.Error(countErr))
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message":   "No medicines found matching the search term",
			"medicines": []Medicine{},
		})
	}

	h.logger.Info("medicines retrieved successfully",
		zap.String("searchTerm", searchTerm),
		zap.Int("count", len(medicines)))

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":   "Medicines retrieved successfully",
		"medicines": medicines,
	})
}
