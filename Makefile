# Variables
APP_NAME = fiber-app
DOCKER_IMAGE = $(APP_NAME):latest

.PHONY: build run clean docker-build docker-run docker-push test lint deps dev generate coolify-prep

# Default target
all: build

# Install dependencies
deps:
	go mod download

# Build the application
build: deps
	go build -o $(APP_NAME) .

# Run the application locally
run: build
	./$(APP_NAME)

# Clean build artifacts
clean:
	rm -f $(APP_NAME)
	go clean

# Build Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE) .

# Run Docker container
docker-run: docker-build
	docker run -p 8080:8080 --env-file .env -e JWT_SECRET=your_jwt_secret_here $(DOCKER_IMAGE)

# Run tests
test:
	go test ./...

# Run linting
lint:
	go vet ./...
	# If you have golangci-lint installed:
	# golangci-lint run

# Development mode - watches for file changes and rebuilds
dev:
	# Requires air (https://github.com/cosmtrek/air)
	# go install github.com/cosmtrek/air@latest
	air -c .air.toml

# Generate models or other code (appears you might have a generator in utils)
generate:
	go run utils/generator.go

# Coolify deployment helpers
coolify-prep:
	@echo "Preparing for Coolify deployment..."
	@echo "Make sure your .env file is not committed to Git"
	@echo "And that environment variables are configured in Coolify"

# Create coolify.yaml file
coolify-yaml:
	@echo "Creating coolify.yaml file..."
	@printf "version: \"3.0\"\nservices:\n  fiber-backend:\n    build:\n      context: .\n      dockerfile: Dockerfile\n    ports:\n      - \"8080:8080\"\n    environment:\n      - JWT_SECRET=your_jwt_secret_here\n    restart: unless-stopped\n    healthcheck:\n      test: [\"CMD\", \"wget\", \"--no-verbose\", \"--tries=1\", \"--spider\", \"http://localhost:8080/health\"]\n      interval: 30s\n      timeout: 10s\n      retries: 5\n" > coolify.yaml
	@echo "coolify.yaml created successfully"