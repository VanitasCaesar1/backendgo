package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	PostgresURL                string
	RedisURL                   string
	KeycloakClientSecret       string
	KeycloakClientID           string
	RealmName                  string
	KeycloakDoctorClientSecret string
	KeycloakDoctorClientId     string
	KeycloakMasterUsername     string
	KeycloakMasterPassword     string
	KeycloakMasterRealm        string
	KeycloakURL                string
	PublicKey                  string
	KeycloakRedirectURL        string
	KeycloakDoctorRedirectURL  string
	ServerPort                 string
	AllowedOrigins             string
	ExpectedIssuer             string
	ExpectedAudience           string
	CookieDomain               string
	Environment                string
	PostLogoutURI              string
	MinioAccessKey             string
	MinioSecretKey             string
	MinioEndpoint              string
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

	// Required environment variables
	requiredVars := []string{
		"KEYCLOAK_URL",
		"REALM_NAME",
		"POSTGRES_URL",
		"REDIS_URL",
		"KEYCLOAK_CLIENT_ID",
		"KEYCLOAK_CLIENT_SECRET",
		"KEYCLOAK_REDIRECT_URL",
	}

	// Check for required environment variables
	for _, v := range requiredVars {
		if os.Getenv(v) == "" {
			return nil, fmt.Errorf("required environment variable %s is not set", v)
		}
	}

	// Initialize config with environment variables
	config := &Config{
		Environment:                env,
		PublicKey:                  string(publicKeyBytes),
		KeycloakURL:                os.Getenv("KEYCLOAK_URL"),
		RealmName:                  os.Getenv("REALM_NAME"),
		AllowedOrigins:             getEnvWithDefault("ALLOWED_ORIGINS", "*"),
		PostgresURL:                os.Getenv("POSTGRES_URL"),
		RedisURL:                   os.Getenv("REDIS_URL"),
		ServerPort:                 getEnvWithDefault("SERVER_PORT", "8080"),
		CookieDomain:               getEnvWithDefault("COOKIE_DOMAIN", ""),
		KeycloakClientID:           os.Getenv("KEYCLOAK_CLIENT_ID"),
		KeycloakDoctorClientSecret: os.Getenv("KEYCLOAK_DOCTOR_CLIENT_SECRET"),
		KeycloakDoctorClientId:     os.Getenv("KEYCLOAK_DOCTOR_CLIENT_ID"),
		KeycloakClientSecret:       os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		KeycloakMasterUsername:     os.Getenv("KEYCLOAK_MASTER_USERNAME"),
		KeycloakMasterPassword:     os.Getenv("KEYCLOAK_MASTER_PASSWORD"),
		KeycloakMasterRealm:        os.Getenv("KEYCLOAK_MASTER_REALM"),
		KeycloakRedirectURL:        os.Getenv("KEYCLOAK_REDIRECT_URL"),
		KeycloakDoctorRedirectURL:  os.Getenv("KEYCLOAK_DOCTOR_REDIRECT_URL"),
		ExpectedIssuer:             os.Getenv("EXPECTED_ISSUER"),
		ExpectedAudience:           os.Getenv("EXPECTED_AUDIENCE"),
		PostLogoutURI:              os.Getenv("POST_LOGOUT_REDIRECT_URI"),
		MinioAccessKey:             os.Getenv("MINIO_ACCESS_KEY"),
		MinioSecretKey:             os.Getenv("MINIO_SECRET_KEY"),
		MinioEndpoint:              os.Getenv("MINIO_ENDPOINT"),
	}

	// Post-process configuration
	// Trim trailing slashes from URLs
	config.KeycloakURL = strings.TrimRight(config.KeycloakURL, "/")
	config.KeycloakRedirectURL = strings.TrimRight(config.KeycloakRedirectURL, "/")

	// If ExpectedIssuer is not set, construct it from KeycloakURL and RealmName
	if config.ExpectedIssuer == "" {
		config.ExpectedIssuer = fmt.Sprintf("%s/realms/%s", config.KeycloakURL, config.RealmName)
	}

	// If ExpectedAudience is not set, use KeycloakClientID
	if config.ExpectedAudience == "" {
		config.ExpectedAudience = config.KeycloakClientID
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
