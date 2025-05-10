# Build stage
FROM golang:1.18-alpine AS builder

# Set working directory
WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev

# Copy go.mod and go.sum files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy the rest of the application
COPY . .

# Build the application
RUN go build -o domain-scanner .

# Final stage
FROM alpine:latest

# Set working directory
WORKDIR /app

# Install CA certificates
RUN apk --no-cache add ca-certificates

# Create directories
RUN mkdir -p /app/output /app/wordlists /app/.cyberops/wordlists

# Copy the binary from the builder stage
COPY --from=builder /app/domain-scanner .

# Add the default wordlist to multiple locations for compatibility
COPY wordlists/subdomains.txt /app/wordlists/subdomains.txt
COPY wordlists/subdomains.txt /app/.cyberops/wordlists/subdomains.txt

# Set the entrypoint with environment variable for wordlist path
ENV WORDLIST_PATH=/app/wordlists/subdomains.txt
ENTRYPOINT ["/app/domain-scanner"]

# Document that the service listens on no port by default
# Provide usage instructions
LABEL maintainer="CyberOps"
LABEL description="Fast, concurrent domain scanner for DNS enumeration and port scanning"
LABEL usage="docker run --rm cyberops/domain-scanner -domain example.com"
