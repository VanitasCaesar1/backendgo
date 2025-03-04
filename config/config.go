package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	PostgresURL string
	RedisURL    string

	PublicKey              string
	ServerPort             string
	AllowedOrigins         string
	ExpectedIssuer         string
	ExpectedAudience       string
	CookieDomain           string
	Environment            string
	PostLogoutURI          string
	MinioAccessKey         string
	MinioSecretKey         string
	MinioEndpoint          string
	MeiliSearch            string
	MongoDBURL             string
	WorkOSApiKey           string
	WorkOSClientId         string
	WorkOSCookiePassword   string
	ApiBaseURL             string
	WorkOSRedirectURI      string
	WorkOSOrganizationsKey string
	WorkOSPasswordlessKey  string
	WorkOSDirectorySyncKey string
	WorkOSAuditLogsKey     string
	WorkOSPortal           string
	WorkOSUserManagement   string
	WorkOSJWKSURL          string
	SessionDuration        string
}

// getEnvWithDefault gets an environment variable with a default value
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	godotenv.Load() // Ignore error since file might not exist in production

	// Load public key from file
	publicKeyPath := os.Getenv("PUBLIC_KEY_PATH")
	if publicKeyPath == "" {
		return nil, fmt.Errorf("PUBLIC_KEY_PATH environment variable is required")
	}

	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}

	// Get environment with default
	env := getEnvWithDefault("ENVIRONMENT", "development")
	env = strings.ToLower(env) // Normalize environment string

	// Validate environment value
	validEnvs := map[string]bool{
		"development": true,
		"staging":     true,
		"production":  true,
	}
	if !validEnvs[env] {
		return nil, fmt.Errorf("invalid environment value: %s", env)
	}

	// Initialize config with environment variables
	config := &Config{
		Environment: env,
		PublicKey:   string(publicKeyBytes),

		AllowedOrigins:         getEnvWithDefault("ALLOWED_ORIGINS", "*"),
		PostgresURL:            os.Getenv("POSTGRES_URL"),
		RedisURL:               os.Getenv("REDIS_URL"),
		ServerPort:             getEnvWithDefault("SERVER_PORT", "8080"),
		CookieDomain:           getEnvWithDefault("COOKIE_DOMAIN", ""),
		ExpectedIssuer:         os.Getenv("EXPECTED_ISSUER"),
		ExpectedAudience:       os.Getenv("EXPECTED_AUDIENCE"),
		MinioAccessKey:         os.Getenv("MINIO_ACCESS_KEY"),
		MinioSecretKey:         os.Getenv("MINIO_SECRET_KEY"),
		MinioEndpoint:          os.Getenv("MINIO_ENDPOINT"),
		MongoDBURL:             os.Getenv("MONGODB_URL"),
		WorkOSApiKey:           os.Getenv("WORKOS_API_KEY"),
		WorkOSClientId:         os.Getenv("WORKOS_CLIENT_ID"),
		WorkOSCookiePassword:   os.Getenv("WORKOS_COOKIE_PASSOWRD"),
		WorkOSRedirectURI:      os.Getenv("WORKOS_REDIRECT_URI"),
		WorkOSOrganizationsKey: os.Getenv("WORKOS_ORGANIZATION_KEY"),
		WorkOSPasswordlessKey:  os.Getenv("WORKOS_PASSWORDLESS_KEY"),
		WorkOSDirectorySyncKey: os.Getenv("WORKOS_DIRECTORY_SYNC_KEY"),
		WorkOSAuditLogsKey:     os.Getenv("WORKOS_AUDIT_LOGS_KEY"),
		WorkOSPortal:           os.Getenv("WORKOS_PORTAL"),
		WorkOSUserManagement:   os.Getenv("WORKOS_USER_M_KEY"),
		WorkOSJWKSURL:          os.Getenv("WORKOS_JWKS_URL"),
		SessionDuration:        getEnvWithDefault("SESSION_DURATION", "12"),
	}

	return config, nil
}

// GetEnvironment returns whether the current environment is development
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsProduction returns whether the current environment is production
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsStaging returns whether the current environment is staging
func (c *Config) IsStaging() bool {
	return c.Environment == "staging"
}
