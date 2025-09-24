# Use Node.js LTS version
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install Doppler CLI - download pre-built binary
RUN apk add --no-cache curl && \
    curl -Ls https://cli.doppler.com/download?os=linux&arch=amd64 -o doppler && \
    chmod +x doppler && \
    mv doppler /usr/local/bin/doppler
# Verify Doppler installation
RUN doppler --version

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

# Start the application with Doppler
CMD ["sh", "-c", "doppler run -- npm run migrate && doppler run -- npm start"]
