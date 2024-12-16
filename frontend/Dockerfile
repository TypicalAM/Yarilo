# syntax=docker/dockerfile:1

FROM node:23.4-bookworm-slim AS builder

# Prepare deps
RUN apt-get update \
	&& apt-get install -y --no-install-recommends git nodejs npm \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Set up workdir
WORKDIR /app

# Copy package deps
COPY package.json package-lock.json .

# Install npm deps
RUN npm ci

# Copy source
COPY . . 

# Build sveltekit
RUN npm run build

FROM node:23.4-bookworm-slim

# Copy deps from builder
COPY --from=builder /app/build /app/build
COPY --from=builder /app/node_modules /app/node_modules

# Install runtime deps
RUN apt-get update \
	&& apt-get install -y --no-install-recommends git nodejs \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["node", "/app/build"]
