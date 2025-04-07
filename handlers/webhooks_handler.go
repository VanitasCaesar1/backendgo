package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/webhooks"
	"go.uber.org/zap"
)

type WorkOSWebhookHandler struct {
	config      *config.Config
	redisClient *redis.Client
	logger      *zap.Logger
	pgPool      *pgxpool.Pool
}

// WebhookEvent represents the structure of a WorkOS webhook event
type WebhookEvent struct {
	ID        string                 `json:"id"`
	Event     string                 `json:"event"`
	Data      OrganizationMembership `json:"data"`
	CreatedAt string                 `json:"created_at"`
}

// OrganizationMembership represents the data for organization membership events
type OrganizationMembership struct {
	ID             string `json:"id"`
	Object         string `json:"object"`
	OrganizationID string `json:"organization_id"`
	UserID         string `json:"user_id"`
	Role           Role   `json:"role"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// Role represents the role information in an organization membership
type Role struct {
	Slug string `json:"slug"`
}

func NewWorkOSWebhookHandler(cfg *config.Config, rds *redis.Client, logger *zap.Logger, pgPool *pgxpool.Pool) *WorkOSWebhookHandler {
	return &WorkOSWebhookHandler{
		config:      cfg,
		redisClient: rds,
		logger:      logger,
		pgPool:      pgPool,
	}
}

// HandleWorkOSWebhook processes incoming WorkOS webhooks
func (h *WorkOSWebhookHandler) HandleWorkOSWebhook(c *fiber.Ctx) error {
	// Get the signature from the header
	signature := c.Get("WorkOS-Signature")
	if signature == "" {
		h.logger.Error("missing WorkOS signature header")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing WorkOS signature",
		})
	}

	// Read the request body
	body, err := io.ReadAll(c.Request().BodyStream())
	if err != nil {
		h.logger.Error("failed to read webhook body", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to read request body",
		})
	}

	// Verify the webhook using the new method
	webhookClient := webhooks.NewClient(h.config.WorkOSWebhookSecret)
	_, err = webhookClient.ValidatePayload(signature, string(body))
	if err != nil {
		h.logger.Error("failed to verify webhook signature", zap.Error(err))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid signature",
		})
	}

	// Parse the webhook event
	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		h.logger.Error("failed to parse webhook event", zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid webhook format",
		})
	}

	h.logger.Info("received WorkOS webhook",
		zap.String("event_id", event.ID),
		zap.String("event_type", event.Event),
		zap.String("user_id", event.Data.UserID))

	// Process based on event type
	switch event.Event {
	case "organization_membership.created":
		err = h.handleOrganizationMembershipCreated(c.Context(), event.Data)
	case "organization_membership.updated":
		err = h.handleOrganizationMembershipUpdated(c.Context(), event.Data)
	case "organization_membership.deleted":
		err = h.handleOrganizationMembershipDeleted(c.Context(), event.Data)
	default:
		h.logger.Info("ignoring unhandled event type", zap.String("event_type", event.Event))
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"success": true,
			"message": "Event acknowledged but not processed",
		})
	}

	if err != nil {
		h.logger.Error("failed to process webhook",
			zap.String("event_type", event.Event),
			zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process webhook",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Webhook processed successfully",
	})
}

// handleOrganizationMembershipCreated processes organization_membership.created events
func (h *WorkOSWebhookHandler) handleOrganizationMembershipCreated(ctx context.Context, data OrganizationMembership) error {
	// First check if user exists in our system
	var userID string
	err := h.pgPool.QueryRow(ctx,
		"SELECT user_id FROM users WHERE auth_id = $1",
		data.UserID).Scan(&userID)
	if err != nil {
		h.logger.Warn("user not found for organization membership",
			zap.String("auth_id", data.UserID))
		return nil // Not an error, just no action taken
	}

	// If the role is 'doctor', update the doctor's active status
	if data.Role.Slug == "doctor" && data.Status == "active" {
		_, err := h.pgPool.Exec(ctx,
			"UPDATE doctors SET is_active = true WHERE doctor_id = $1",
			userID)
		if err != nil {
			return fmt.Errorf("failed to update doctor status: %w", err)
		}

		h.logger.Info("activated doctor account via organization membership",
			zap.String("user_id", userID),
			zap.String("auth_id", data.UserID))
	}

	// Store the organization membership ID in your database if needed
	// This example assumes you have a column for tracking org memberships
	_, err = h.pgPool.Exec(ctx,
		`INSERT INTO user_organization_memberships 
		(user_id, organization_id, membership_id, role, status) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, organization_id) 
		DO UPDATE SET membership_id = $3, role = $4, status = $5`,
		userID, data.OrganizationID, data.ID, data.Role.Slug, data.Status)
	if err != nil {
		return fmt.Errorf("failed to store organization membership: %w", err)
	}

	return nil
}

// handleOrganizationMembershipUpdated processes organization_membership.updated events
func (h *WorkOSWebhookHandler) handleOrganizationMembershipUpdated(ctx context.Context, data OrganizationMembership) error {
	// First check if user exists in our system
	var userID string
	err := h.pgPool.QueryRow(ctx,
		"SELECT user_id FROM users WHERE auth_id = $1",
		data.UserID).Scan(&userID)
	if err != nil {
		h.logger.Warn("user not found for organization membership update",
			zap.String("auth_id", data.UserID))
		return nil // Not an error, just no action taken
	}

	// If the role is 'doctor', update doctor status based on membership status
	if data.Role.Slug == "doctor" {
		isActive := data.Status == "active"
		_, err := h.pgPool.Exec(ctx,
			"UPDATE doctors SET is_active = $1 WHERE doctor_id = $2",
			isActive, userID)
		if err != nil {
			return fmt.Errorf("failed to update doctor status: %w", err)
		}

		h.logger.Info("updated doctor active status via organization membership",
			zap.String("user_id", userID),
			zap.String("auth_id", data.UserID),
			zap.Bool("is_active", isActive))
	}

	// Update the membership information in your database
	_, err = h.pgPool.Exec(ctx,
		`UPDATE user_organization_memberships 
		SET role = $1, status = $2, membership_id = $3
		WHERE user_id = $4 AND organization_id = $5`,
		data.Role.Slug, data.Status, data.ID, userID, data.OrganizationID)
	if err != nil {
		return fmt.Errorf("failed to update organization membership: %w", err)
	}

	return nil
}

// handleOrganizationMembershipDeleted processes organization_membership.deleted events
func (h *WorkOSWebhookHandler) handleOrganizationMembershipDeleted(ctx context.Context, data OrganizationMembership) error {
	// First check if user exists in our system
	var userID string
	err := h.pgPool.QueryRow(ctx,
		"SELECT user_id FROM users WHERE auth_id = $1",
		data.UserID).Scan(&userID)
	if err != nil {
		h.logger.Warn("user not found for organization membership deletion",
			zap.String("auth_id", data.UserID))
		return nil // Not an error, just no action taken
	}

	// If the role was 'doctor', set their active status to false
	if data.Role.Slug == "doctor" {
		_, err := h.pgPool.Exec(ctx,
			"UPDATE doctors SET is_active = false WHERE doctor_id = $1",
			userID)
		if err != nil {
			return fmt.Errorf("failed to deactivate doctor: %w", err)
		}

		h.logger.Info("deactivated doctor account via organization membership deletion",
			zap.String("user_id", userID),
			zap.String("auth_id", data.UserID))
	}

	// Remove the membership from your database
	_, err = h.pgPool.Exec(ctx,
		`DELETE FROM user_organization_memberships 
		WHERE user_id = $1 AND organization_id = $2`,
		userID, data.OrganizationID)
	if err != nil {
		return fmt.Errorf("failed to delete organization membership: %w", err)
	}

	return nil
}
