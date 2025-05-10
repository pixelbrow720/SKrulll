# Base Dockerfile template for Node.js components

FROM node:16-alpine as builder

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci

# Copy the rest of the application
COPY . .

# Build the application if needed
RUN npm run build

# Final stage
FROM node:16-alpine

# Set working directory
WORKDIR /app

# Install production dependencies only
COPY package.json package-lock.json* ./
RUN npm ci --only=production

# Copy built application from builder stage
COPY --from=builder /app/dist /app/dist

# Expose any required ports
# EXPOSE 8000

# Set the entrypoint
ENTRYPOINT ["node"]

# Set the default command
CMD ["dist/index.js"]
