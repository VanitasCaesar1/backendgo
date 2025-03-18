# Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /app
# Install git and other dependencies needed for go mod
RUN apk add --no-cache git ca-certificates tzdata
# Copy go mod and sum files
COPY go.mod go.sum ./
# Set environment variables to enable Go modules
ENV GO111MODULE=on
ENV GOPROXY=https://proxy.golang.org,direct
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
# Create config directory and copy config files
COPY --from=builder /app/config ./config
# Create public directory if you have static files
RUN mkdir -p ./public
# Set JWT authentication environment variable directly
# Use this for HMAC-based JWT authentication instead of RSA/ECDSA with PEM files
ENV JWT_SECRET=your_jwt_secret_here
# Expose the port your app runs on
EXPOSE 8080
# Command to run the executable
CMD ["./main"]