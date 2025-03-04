package handlers

import (
	"github.com/VanitasCaesar1/backend/cache"
	"github.com/VanitasCaesar1/backend/config"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type AuthHandler struct {
	logger  *zap.Logger
	cache   *cache.Cache
	config  *config.Config
	redis   *redis.Client
	session *session.Store
	pgxpool *pgxpool.Pool
}

type AuthHandlerInterface interface {
	Login()
	Logout()
	Refresh()
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Sessioncookie string `json:"sessioncookie"`
}

type LogoutRequest struct {
	Sessioncookie string `json:"sessioncookie"`
}

func NewAuthHandler(logger *zap.Logger, cache *cache.Cache, config *config.Config, redis *redis.Client, session *session.Store, pgxpool *pgxpool.Pool) *AuthHandler {

	return &AuthHandler{
		logger:  logger,
		cache:   cache,
		config:  config,
		redis:   redis,
		session: session,
		pgxpool: pgxpool,
	}
}
