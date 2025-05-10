
# Optimized Node.js Dockerfile for CyberOps

# Build stage
FROM node:18-slim AS builder

# Set work directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci --only=production

# Copy the rest of the application
COPY . .

# Build the application (if needed)
RUN npm run build --if-present

# Remove development files
RUN find . -name "*.test.js" -type f -delete && \
    find . -name "*.spec.js" -type f -delete && \
    rm -rf node_modules/.cache && \
    rm -rf tests && \
    rm -rf docs

# Runtime stage
FROM node:18-alpine AS runtime

# Set work directory
WORKDIR /app

# Set environment variables
ENV NODE_ENV=production

# Copy built application from builder
COPY --from=builder /app /app

# Set user to non-root
USER node

# Default command
CMD ["node", "main.js"]
