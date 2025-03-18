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
ENV JWT_SECRET=dd51917c15ef8579fdffb089c54fc17915d1eaec4d5b6ba16551b2f597fa464d6595b34ea08d34f7e1950c4fb313d81022fc870143caf250d4fe5eb94a85b666933469a6629055f60de54b061b609232322a659391671819bb54d6e6ef91e28226faa4f545e147ad4564faf13e28aa87bc13f3d3c1b1896559e5b897ef769c5d9285864e16b8fc6f15a6e404589433d01839368fe431c8a46eae997888255424296b8585ca53e93d6148ff17ef60f91b5b37cfa12fb9077c8b813fc2f26741caa24d48d6641177eceeb23f16472eedd7dd38f5c18b64d350240be65f3ff6963a865fe1c1518c13117c4eb78124c152722a27eaaed0c753c25c21a869b0102419
# Expose the port your app runs on
EXPOSE 8080
# Command to run the executable
CMD ["./main"]