# Base Dockerfile template for Python components

FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    POETRY_VERSION=1.2.2 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        curl \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry for dependency management
RUN curl -sSL https://install.python-poetry.org | python3 -

# Copy just the pyproject.toml and poetry.lock (if available)
COPY pyproject.toml poetry.lock* /app/

# Install dependencies
RUN poetry install --no-dev

# Copy the rest of the application
COPY . /app/

# Add the application to the Python path
ENV PYTHONPATH=/app

# Set the entrypoint
ENTRYPOINT ["python"]

# Set the default command
CMD ["main.py"]
