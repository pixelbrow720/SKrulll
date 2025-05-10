
# Optimized Go Dockerfile for SKrulll

# Build stage
FROM golang:1.20-alpine AS builder

# Set work directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy Go module files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -o bin/app \
    ./cmd/app

# Runtime stage
FROM alpine:latest AS runtime

# Set work directory
WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy built binary from builder
COPY --from=builder /app/bin/app /app/app

# Copy configuration files
COPY config/*.json /app/config/

# Set executable permissions
RUN chmod +x /app/app

# Default command
CMD ["/app/app"]
