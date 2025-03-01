package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2/middleware/limiter"

	"github.com/VanitasCaesar1/backend/config"
	"github.com/VanitasCaesar1/backend/handlers"
	"github.com/VanitasCaesar1/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"
	"github.com/workos/workos-go/v4/pkg/auditlogs"
	"github.com/workos/workos-go/v4/pkg/directorysync"
	"github.com/workos/workos-go/v4/pkg/organizations"
	"github.com/workos/workos-go/v4/pkg/passwordless"
	"github.com/workos/workos-go/v4/pkg/portal"
	"github.com/workos/workos-go/v4/pkg/sso"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
	"go.uber.org/zap"
)

type App struct {
	Fiber        *fiber.App
	Postgres     *pgxpool.Pool
	Redis        *redis.Client
	MinioClient  *minio.Client
	Ctx          context.Context
	Config       *config.Config
	Logger       *zap.Logger
	WorkosClient *sso.Client
}

func NewApp() (*App, error) {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	// Initialize WorkOS AuthKit - assuming this returns *sso.Client
	// Call AuthkitInit without capturing the return value
	AuthkitInit(*cfg)

	// Use the DefaultClient variable directly - it's not a function in v4
	workosClient := sso.DefaultClient

	// Setup context with cancellation
	ctx := context.Background()

	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %v", err)
	}

	// Setup PostgreSQL connection with retry logic
	var pgPool *pgxpool.Pool
	maxRetries := 5

	// Create pool config
	poolConfig, err := pgxpool.ParseConfig(cfg.PostgresURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse pool config: %v", err)
	}

	// Configure pool settings
	poolConfig.MaxConns = 10
	poolConfig.MinConns = 2
	poolConfig.MaxConnLifetime = time.Hour
	poolConfig.MaxConnIdleTime = 30 * time.Minute

	for i := 0; i < maxRetries; i++ {
		pgPool, err = pgxpool.NewWithConfig(ctx, poolConfig)
		if err == nil {
			// Test the connection
			if err := pgPool.Ping(ctx); err == nil {
				break
			}
			pgPool.Close()
		}
		logger.Warn("failed to connect to postgres, retrying...",
			zap.Error(err),
			zap.Int("attempt", i+1))
		time.Sleep(time.Second * time.Duration(i+1))
	}
	if err != nil {
		return nil, fmt.Errorf("postgres connection failed after %d attempts: %v", maxRetries, err)
	}

	// Setup Redis connection with retry logic
	redisOpt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("redis URL parsing failed: %v", err)
	}

	redisClient := redis.NewClient(redisOpt)
	maxRedisRetries := 5
	for i := 0; i < maxRedisRetries; i++ {
		_, err = redisClient.Ping(ctx).Result()
		if err == nil {
			break
		}
		logger.Warn("failed to connect to redis, retrying...",
			zap.Error(err),
			zap.Int("attempt", i+1))
		time.Sleep(time.Second * time.Duration(i+1))
	}
	if err != nil {
		return nil, fmt.Errorf("redis connection failed after %d attempts: %v", maxRedisRetries, err)
	}

	// Setup MinIO connection with retry logic
	var minioClient *minio.Client
	maxMinioRetries := 5
	for i := 0; i < maxMinioRetries; i++ {
		minioClient, err = minio.New(cfg.MinioEndpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
			Secure: true,
			Region: "india-s-1",
		})
		if err != nil {
			logger.Warn("failed to create minio client, retrying...",
				zap.Error(err),
				zap.Int("attempt", i+1))
			time.Sleep(time.Second * time.Duration(i+1))
			continue
		}
		break
	}

	if err != nil {
		return nil, fmt.Errorf("minio connection failed after %d attempts: %v", maxMinioRetries, err)
	}

	// Create required buckets
	requiredBuckets := []string{"profile-pics", "hospital-pics"}
	for _, bucket := range requiredBuckets {
		// Check if bucket exists - handle the "Found" case properly
		exists, err := minioClient.BucketExists(ctx, bucket)
		if err != nil {
			if err.Error() == "Found" {
				logger.Info("bucket verified",
					zap.String("bucket", bucket))
				continue
			}
			logger.Error("failed to check bucket existence",
				zap.String("bucket", bucket),
				zap.Error(err))
			continue
		}

		if exists {
			logger.Info("bucket verified",
				zap.String("bucket", bucket))
			continue
		}

		// Create bucket if it doesn't exist
		err = minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			logger.Error("failed to create bucket",
				zap.String("bucket", bucket),
				zap.Error(err))
		} else {
			logger.Info("bucket created",
				zap.String("bucket", bucket))
		}
	}

	// Fiber setup with improved error handling
	fiberApp := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			logger.Error("request error",
				zap.Error(err),
				zap.String("path", c.Path()),
				zap.Int("status", code))
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
	})

	// Add recover middleware
	fiberApp.Use(recover.New())

	// CORS configuration
	fiberApp.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
		ExposeHeaders:    "Set-Cookie",
		MaxAge:           300,
	}))

	// CSP configuration
	fiberApp.Use(func(c *fiber.Ctx) error {
		c.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"connect-src 'self' http://localhost:3000 http://localhost:8080; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'")
		return c.Next()
	})

	// In your Fiber app setup
	fiberApp.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP() // Rate limit by IP
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Rate limit exceeded",
				"code":  "RATE_LIMIT_EXCEEDED",
			})
		},
	}))

	// Request logging middleware
	fiberApp.Use(func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		duration := time.Since(start)

		logger.Info("request completed",
			zap.String("method", c.Method()),
			zap.String("path", c.Path()),
			zap.String("ip", c.IP()),
			zap.Duration("duration", duration),
			zap.Int("status", c.Response().StatusCode()),
		)
		return err
	})

	return &App{
		Fiber:        fiberApp,
		Postgres:     pgPool,
		Redis:        redisClient,
		MinioClient:  minioClient,
		Ctx:          ctx,
		Config:       cfg,
		Logger:       logger,
		WorkosClient: workosClient,
	}, nil
}

func (a *App) setupRoutes() error {
	// Setup the auth middleware with WorkOS client
	// Update: Handle both the middleware and error return values
	authMiddleware, err := middleware.NewAuthMiddleware(middleware.AuthMiddlewareConfig{
		Logger:       a.Logger,
		Redis:        a.Redis,
		Config:       a.Config,
		CookieName:   "wos-session", // Changed from "session" to "wos-session"
		WorkosClient: a.WorkosClient,
		ClientID:     a.Config.WorkOSClientId, // Added ClientID from config
	})

	if err != nil {
		return fmt.Errorf("failed to initialize auth middleware: %v", err)
	}

	// User handler
	userHandler, err := handlers.NewUserHandler(a.Config, a.Redis, a.Logger, a.Postgres)
	if err != nil {
		return fmt.Errorf("failed to initialize user handler: %v", err)
	}

	// Regular API routes - use auth middleware
	api := a.Fiber.Group("/api", authMiddleware.Handler())
	userGroup := api.Group("/user")
	userGroup.Get("/profile", userHandler.GetUserProfile)
	userGroup.Put("/profile", userHandler.UpdateUserProfile)
	userGroup.Post("/profile/picture", userHandler.UploadProfilePic)
	userGroup.Get("/profile/picture/:filename", userHandler.GetProfilePic)

	return nil
}

func (a *App) Start() error {
	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Setup routes
	if err := a.setupRoutes(); err != nil {
		return fmt.Errorf("failed to setup routes: %v", err)
	}

	// Start server in a goroutine
	go func() {
		if err := a.Fiber.Listen(":" + a.Config.ServerPort); err != nil {
			a.Logger.Fatal("failed to start server",
				zap.Error(err),
				zap.String("port", a.Config.ServerPort))
		}
	}()

	a.Logger.Info("server started",
		zap.String("port", a.Config.ServerPort))

	// Wait for interrupt signal
	<-sigChan
	a.Logger.Info("shutting down server...")

	// Cleanup
	if err := a.Fiber.Shutdown(); err != nil {
		a.Logger.Error("error during server shutdown",
			zap.Error(err))
	}
	a.Postgres.Close()
	if err := a.Redis.Close(); err != nil {
		a.Logger.Error("error closing redis connection",
			zap.Error(err))
	}
	if err := a.Logger.Sync(); err != nil {
		log.Printf("error syncing logger: %v", err)
	}

	return nil
}

func main() {
	app, err := NewApp()
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	if err := app.Start(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func AuthkitInit(cfg config.Config) {
	// Initialize SSO with client ID and API key
	sso.Configure(
		cfg.WorkOSClientId,
		cfg.WorkOSApiKey,
	)

	// Set API keys for other WorkOS services
	organizations.SetAPIKey(cfg.WorkOSOrganizationsKey)
	passwordless.SetAPIKey(cfg.WorkOSPasswordlessKey)
	directorysync.SetAPIKey(cfg.WorkOSDirectorySyncKey)
	usermanagement.SetAPIKey(cfg.WorkOSUserManagement)
	auditlogs.SetAPIKey(cfg.WorkOSAuditLogsKey)
	portal.SetAPIKey(cfg.WorkOSPortal)
}
