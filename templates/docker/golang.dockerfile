# Base Dockerfile template for Go components

FROM golang:1.18-alpine AS builder

# Set working directory
WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go.mod and go.sum files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy the rest of the application
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# Final stage
FROM alpine:latest

# Set working directory
WORKDIR /app

# Install CA certificates
RUN apk --no-cache add ca-certificates

# Copy the binary from the builder stage
COPY --from=builder /app/app .

# Expose any required ports
# EXPOSE 8000

# Set the entrypoint
ENTRYPOINT ["/app/app"]
