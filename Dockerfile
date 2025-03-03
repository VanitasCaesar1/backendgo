# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:latest

WORKDIR /app

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Copy the binary from builder
COPY --from=builder /app/main .
# Copy the public key for JWT authentication
COPY --from=builder /app/public_key.pem .
# Create config directory and copy config files
COPY --from=builder /app/config ./config
# Create public directory if you have static files
RUN mkdir -p ./public

# Expose the port your app runs on
EXPOSE 8080

# Command to run the executable
CMD ["./main"]