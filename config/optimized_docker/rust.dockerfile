
# Optimized Rust Dockerfile for CyberOps

# Build stage
FROM rust:1.70-slim AS builder

# Set work directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files
COPY Cargo.toml Cargo.lock* ./

# Create blank lib for caching dependencies
RUN mkdir -p src && \
    echo "fn main() {println!(\"if you see this, cargo build has failed\")}" > src/main.rs && \
    echo "pub fn lib() {}" > src/lib.rs

# Build dependencies
RUN cargo build --release

# Remove the temporary source files
RUN rm -f src/main.rs src/lib.rs

# Copy actual source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bullseye-slim AS runtime

# Set work directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary
COPY --from=builder /app/target/release/app /app/app

# Copy configuration files
COPY config/*.toml /app/config/

# Set executable permissions
RUN chmod +x /app/app

# Default command
CMD ["/app/app"]
