# Use Node.js LTS version
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Note: Doppler CLI installation skipped for Render deployment
# JWT_SECRET will be provided via environment variables

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Remove dev dependencies after build
RUN npm prune --production

# Expose port
EXPOSE 3000

# Start the application
CMD ["sh", "-c", "npm run migrate && npm start"]
