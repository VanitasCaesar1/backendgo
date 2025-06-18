package handlers

import (
	"context"
	"fmt"
	"strconv"
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

// Enhanced SearchMedicines with comprehensive debugging - matches from first character
func (h *MedicineHandler) SearchMedicines(c *fiber.Ctx) error {
	// Get search term from query parameter
	searchTerm := c.Query("term")
	if searchTerm == "" {
		h.logger.Error("search term is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Search term is required"})
	}

	// Log the exact search term received
	h.logger.Info("searching medicines",
		zap.String("searchTerm", searchTerm),
		zap.String("searchTermLength", fmt.Sprintf("%d", len(searchTerm))),
		zap.String("searchTermBytes", fmt.Sprintf("%x", []byte(searchTerm))))

	// Get additional filters
	company := c.Query("company")
	unit := c.Query("unit")
	limitStr := c.Query("limit", "50")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 50
	}

	h.logger.Info("search parameters",
		zap.String("company", company),
		zap.String("unit", unit),
		zap.Int("limit", limit))

	// Create context with timeout
	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	// Build dynamic query based on filters
	baseQuery := `
		SELECT id,
			COALESCE(code, '') as code,
			COALESCE(name, '') as name,
			COALESCE(unit, '') as unit,
			COALESCE(company, '') as company
		FROM public.medicines
		WHERE (
			COALESCE(name, '') ILIKE $1 OR
			COALESCE(code, '') ILIKE $1 OR
			COALESCE(company, '') ILIKE $1
		)`

	var args []interface{}
	argIndex := 2

	// Add wildcard pattern for LIKE search - matches from first character
	pattern := fmt.Sprintf("%s%%", searchTerm) // Changed from %%%s%% to %s%%
	args = append(args, pattern)

	// Add company filter if provided
	if company != "" {
		baseQuery += fmt.Sprintf(" AND COALESCE(company, '') ILIKE $%d", argIndex)
		args = append(args, fmt.Sprintf("%s%%", company)) // Also changed for consistency
		argIndex++
	}

	// Add unit filter if provided
	if unit != "" {
		baseQuery += fmt.Sprintf(" AND COALESCE(unit, '') ILIKE $%d", argIndex)
		args = append(args, fmt.Sprintf("%s%%", unit)) // Also changed for consistency
		argIndex++
	}

	// Add ordering and limit
	baseQuery += fmt.Sprintf(" ORDER BY name ASC LIMIT $%d", argIndex)
	args = append(args, limit)

	h.logger.Debug("executing database query",
		zap.String("query", baseQuery),
		zap.String("pattern", pattern),
		zap.Any("args", args))

	// First, let's test if the table has data and our connection works
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM public.medicines"
	if err := h.pgPool.QueryRow(ctx, countQuery).Scan(&totalCount); err != nil {
		h.logger.Error("failed to count total medicines", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection issue",
		})
	}
	h.logger.Info("total medicines in database", zap.Int("totalCount", totalCount))

	// Test a simple query to see if basic search works
	testQuery := `SELECT COUNT(*) FROM public.medicines WHERE COALESCE(name, '') ILIKE $1`
	var matchCount int
	if err := h.pgPool.QueryRow(ctx, testQuery, pattern).Scan(&matchCount); err != nil {
		h.logger.Error("failed to test pattern matching", zap.Error(err))
	} else {
		h.logger.Info("pattern match test",
			zap.String("pattern", pattern),
			zap.Int("matchCount", matchCount))
	}

	// Execute the main query
	rows, err := h.pgPool.Query(ctx, baseQuery, args...)
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
	rowCount := 0
	for rows.Next() {
		var med Medicine
		if err := rows.Scan(&med.ID, &med.Code, &med.Name, &med.Unit, &med.Company); err != nil {
			h.logger.Error("failed to scan medicine row",
				zap.Error(err),
				zap.String("errorType", "row_scan_error"))
			continue
		}
		medicines = append(medicines, med)
		rowCount++

		// Log first few results for debugging
		if rowCount <= 3 {
			h.logger.Debug("found medicine",
				zap.Int("id", med.ID),
				zap.String("name", med.Name),
				zap.String("code", med.Code),
				zap.String("company", med.Company))
		}
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

	h.logger.Info("search completed",
		zap.String("searchTerm", searchTerm),
		zap.Int("resultsFound", len(medicines)),
		zap.Int("totalInDatabase", totalCount))

	// Return results (even if empty)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":   fmt.Sprintf("Found %d medicines matching '%s'", len(medicines), searchTerm),
		"medicines": medicines,
		"debug": fiber.Map{
			"searchTerm":      searchTerm,
			"pattern":         pattern,
			"totalInDatabase": totalCount,
			"resultsFound":    len(medicines),
		},
	})
}
