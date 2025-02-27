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
	"github.com/workos/workos-go/v4/pkg/sso"
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
	// Configure client types
	clientTypes := map[string]string{
		"web-client-123":    string(middleware.WebApp),
		"mobile-client-123": string(middleware.MobileApp),
		"user-client-123":   string(middleware.UserClient),
		"doctor-client-123": string(middleware.DoctorClient),
		"admin-client-123":  string(middleware.AdminPanel),
	}

	// Configure cookie names
	cookieNames := map[middleware.ClientType]string{
		middleware.WebApp:       "hospital_web_session",
		middleware.MobileApp:    "doctor_web_session",
		middleware.UserClient:   "user_mobile_session",
		middleware.DoctorClient: "doctor_mobile_session",
		middleware.AdminPanel:   "admin_session",
	}

	// Setup the new auth middleware
	authMiddleware := middleware.NewAuthMiddleware(middleware.AuthMiddlewareConfig{
		Logger:      a.Logger,
		Redis:       a.Redis,
		Config:      a.Config,
		ClientTypes: clientTypes,
		CookieNames: cookieNames,
		// WorkOS client is now handled internally in the middleware
	})

	// Regular auth handler with WorkOS integration
	authHandler, err := handlers.NewAuthHandler(a.Config, a.Redis, a.Logger, "user", "auth_session")
	if err != nil {
		return fmt.Errorf("failed to initialize auth handler: %v", err)
	}

	// Doctor auth handler
	doctorAuthHandler, err := handlers.NewDoctorAuthHandler(a.Config, a.Redis, a.Postgres, a.Logger)
	if err != nil {
		return fmt.Errorf("failed to initialize doctor auth handler: %v", err)
	}

	// User handler
	userHandler, err := handlers.NewUserHandler(a.Config, a.Redis, a.Logger, authHandler, a.Postgres)
	if err != nil {
		return fmt.Errorf("failed to initialize user handler: %v", err)
	}

	// Regular auth routes
	auth := a.Fiber.Group("/auth")
	auth.Get("/login", authHandler.Login)
	auth.Get("/callback", authHandler.Callback)
	auth.Post("/callback", authHandler.Callback)
	auth.Post("/logout", authHandler.Logout)
	auth.Get("/user", authHandler.AuthMiddleware, authHandler.GetUserInfo)
	auth.Get("/validate", authHandler.ValidateSession) // Fixed path to match usage

	// Regular API routes - use new auth middleware
	api := a.Fiber.Group("/api", authMiddleware.Handler())
	userGroup := api.Group("/user")
	userGroup.Get("/profile", userHandler.GetUserProfile)
	userGroup.Put("/profile", userHandler.UpdateUserProfile)
	userGroup.Post("/profile/picture", userHandler.UploadProfilePic)

	a.Fiber.Get("/api/media/profile-pics/:filename", userHandler.GetProfilePic)

	// Doctor auth routes - no middleware for auth endpoints
	doctorAuth := a.Fiber.Group("/auth/doctor")
	doctorAuth.Post("/register", doctorAuthHandler.Register)
	doctorAuth.Post("/login", doctorAuthHandler.Login)
	doctorAuth.Get("/callback", doctorAuthHandler.Callback)
	doctorAuth.Post("/callback", doctorAuthHandler.Callback)
	doctorAuth.Post("/logout", doctorAuthHandler.Logout)

	// Doctor API routes - use the new auth middleware with doctor client type
	//doctorApi := a.Fiber.Group("/api/doctor", authMiddleware.Handler())
	// Add doctor-specific routes here

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
