FROM golang:1.20-alpine

# Set environment variables
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
ENV GO111MODULE=on

# Install system dependencies
RUN apk add --no-cache git ca-certificates curl

# Create and set working directory
WORKDIR /app

# Copy go module files
COPY modules/vulnerability/api_tester/go.mod .
COPY modules/vulnerability/api_tester/go.sum* .

# Download dependencies
RUN go mod download

# Copy source code
COPY modules/vulnerability/api_tester/*.go .

# Copy templates and configs (if any)
COPY modules/vulnerability/api_tester/*.json ./
COPY modules/vulnerability/api_tester/*.yaml* ./

# Create directory for reports
RUN mkdir -p /app/reports

# Build the application
RUN go build -o api-tester .

# Use a smaller image for the final stage
FROM alpine:3.18

# Install CA certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Create app directories
WORKDIR /app
RUN mkdir -p /app/reports

# Copy the binary from the build stage
COPY --from=0 /app/api-tester /app/
COPY --from=0 /app/*.json /app/
COPY --from=0 /app/*.yaml* /app/

# Expose port if needed
EXPOSE 8080

# Set the entry point
ENTRYPOINT ["/app/api-tester"]