# Multi-stage build for the network mapper
FROM rust:1.63-slim as rust_builder

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        python3 \
        python3-dev \
        python3-pip \
        libpython3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo.toml and the source code
COPY Cargo.toml .
COPY src/ src/

# Build the binary
RUN cargo build --release

# Build the Python bindings
RUN cargo build --release --features python

# Second stage: Python with Rust libraries
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        libpcap-dev \
        graphviz \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy the Rust binary and library
COPY --from=rust_builder /app/target/release/network_mapper /app/
COPY --from=rust_builder /app/target/release/libnetwork_mapper.so /app/

# Copy Python binding code
COPY python_bindings/ /app/python_bindings/

# Install Python dependencies
RUN pip install --no-cache-dir \
    python-nmap \
    graphviz \
    neo4j \
    pydot

# Create symbolic link for the Python module
RUN ln -s /app/libnetwork_mapper.so /app/python_bindings/network_mapper.so

# Set Python path
ENV PYTHONPATH=/app:$PYTHONPATH

# Set entrypoint
ENTRYPOINT ["python3", "/app/python_bindings/network_mapper.py"]

# Document that the service listens on no port by default
LABEL maintainer="CyberOps"
LABEL description="High-speed network discovery and mapping tool with Rust and Python"
LABEL usage="docker run --rm --net=host cyberops/network-mapper 192.168.1.0/24"