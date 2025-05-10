
# Optimized Python Dockerfile for CyberOps

# Build stage
FROM python:3.10-slim AS builder

# Set work directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements file first to leverage Docker cache
COPY requirements.txt .
COPY pyproject.toml poetry.lock* ./

# Install dependencies into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir poetry && \
    poetry export -f requirements.txt --without-hashes > requirements-prod.txt && \
    pip install --no-cache-dir -r requirements-prod.txt

# Copy the rest of the application
COPY . .

# Compile Python bytecode
RUN python -m compileall .

# Runtime stage
FROM python:3.10-slim AS runtime

# Set work directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application from builder
COPY --from=builder /app /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONOPTIMIZE=2

# Default command
CMD ["python", "main.py"]
