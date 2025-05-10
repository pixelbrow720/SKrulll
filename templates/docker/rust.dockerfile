# Base Dockerfile template for Rust components

FROM rust:1.63-slim as builder

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo.toml and Cargo.lock
COPY Cargo.toml Cargo.lock* ./

# Create empty src/main.rs to build dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy the actual source code
COPY . .

# Build the application
RUN cargo build --release

# Final stage
FROM debian:bullseye-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl1.1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/app .

# Expose any required ports
# EXPOSE 8000

# Set the entrypoint
ENTRYPOINT ["/app/app"]
