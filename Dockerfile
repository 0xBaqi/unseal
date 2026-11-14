# Unseal — Production Container Dockerfile
FROM node:22-alpine

# Install curl, certificates, bash, and cloudflared binary
RUN apk add --no-cache curl ca-certificates bash \
    && curl -L --output /usr/local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    && chmod +x /usr/local/bin/cloudflared

WORKDIR /app

# Copy dependency definitions
COPY package.json package-lock.json ./

# Install clean production dependencies
RUN npm ci

# Copy project files
COPY . .

# Build frontend bundle
RUN npm run build

# Ensure data persistence directory exists
RUN mkdir -p data

EXPOSE 3000

ENV PORT=3000
ENV HOST=0.0.0.0

CMD ["./start.sh"]
